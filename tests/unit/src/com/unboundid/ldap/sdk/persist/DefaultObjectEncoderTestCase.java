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



import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.GregorianCalendar;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides test coverage for the {@code DefaultObjectEncoder}
 * class.
 */
public class DefaultObjectEncoderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for processing related to {@code AtomicInteger}
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAtomicIntegerField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("atomicIntF");
    assertNotNull(f);


    AtomicInteger i = new AtomicInteger(1);
    assertTrue(e.supportsType(i.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "atomicintf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "atomicIntF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, i, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1"));
    assertFalse(a.hasValue("2"));


    // Test the decodeField method with a single value.
    assertNull(o.getAtomicIntF());

    e.decodeField(f, o, a);

    assertNotNull(o.getAtomicIntF());
    assertEquals(o.getAtomicIntF().intValue(), 1);
  }



  /**
   * Provides test coverage for processing related to {@code AtomicInteger}
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAtomicIntegerArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("atomicIntAF");
    assertNotNull(f);


    AtomicInteger[] i = new AtomicInteger[2];
    i[0] = new AtomicInteger(2);
    i[1] = new AtomicInteger(3);
    assertTrue(e.supportsType(i.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "atomicintaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "atomicIntAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, i, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertFalse(a.hasValue("1"));
    assertTrue(a.hasValue("2"));
    assertTrue(a.hasValue("3"));


    // Test the decodeField method with multiple values.
    assertNull(o.getAtomicIntAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getAtomicIntAF());
    assertEquals(o.getAtomicIntAF().length, 2);
    assertEquals(o.getAtomicIntAF()[0].intValue(), 2);
    assertEquals(o.getAtomicIntAF()[1].intValue(), 3);
  }



  /**
   * Provides test coverage for processing related to {@code AtomicInteger}
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAtomicIntegerGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getAtomicIntM");
    assertNotNull(m);

    AtomicInteger i = new AtomicInteger(1);
    assertTrue(e.supportsType(i.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "atomicintm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "atomicIntM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, i, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1"));
    assertFalse(a.hasValue("2"));
  }



  /**
   * Provides test coverage for processing related to {@code AtomicInteger}
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAtomicIntegerArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getAtomicIntAM");
    assertNotNull(m);

    AtomicInteger[] i = new AtomicInteger[2];
    i[0] = new AtomicInteger(2);
    i[1] = new AtomicInteger(3);
    assertTrue(e.supportsType(i.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "atomicintam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "atomicIntAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, i, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertFalse(a.hasValue("1"));
    assertTrue(a.hasValue("2"));
    assertTrue(a.hasValue("3"));
  }



  /**
   * Provides test coverage for processing related to {@code AtomicInteger}
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAtomicIntegerSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setAtomicIntM",
         AtomicInteger.class);
    assertNotNull(m);

    AtomicInteger i = new AtomicInteger(1);
    assertTrue(e.supportsType(i.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getAtomicIntM());

    e.invokeSetter(m, o, new Attribute("foo", "4"));

    assertNotNull(o.getAtomicIntM());
    assertEquals(o.getAtomicIntM().intValue(), 4);
  }



  /**
   * Provides test coverage for processing related to {@code AtomicInteger}
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAtomicIntegerArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    AtomicInteger[] i = new AtomicInteger[2];
    i[0] = new AtomicInteger(2);
    i[1] = new AtomicInteger(3);
    assertTrue(e.supportsType(i.getClass()));

    Method m = o.getClass().getDeclaredMethod("setAtomicIntAM", i.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getAtomicIntAM());

    e.invokeSetter(m, o, new Attribute("foo", "4", "5"));

    assertNotNull(o.getAtomicIntAM());
    assertEquals(o.getAtomicIntAM().length, 2);
    assertEquals(o.getAtomicIntAM()[0].intValue(), 4);
    assertEquals(o.getAtomicIntAM()[1].intValue(), 5);
  }



  /**
   * Provides test coverage for processing related to {@code AtomicLong} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAtomicLongField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("atomicLongF");
    assertNotNull(f);


    AtomicLong l = new AtomicLong(1L);
    assertTrue(e.supportsType(l.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "atomiclongf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "atomicLongF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, l, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1"));
    assertFalse(a.hasValue("2"));


    // Test the decodeField method with a single value.
    assertNull(o.getAtomicLongF());

    e.decodeField(f, o, a);

    assertNotNull(o.getAtomicLongF());
    assertEquals(o.getAtomicLongF().longValue(), 1L);
  }



  /**
   * Provides test coverage for processing related to {@code AtomicLong} array
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAtomicLongArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("atomicLongAF");
    assertNotNull(f);


    AtomicLong[] l = new AtomicLong[2];
    l[0] = new AtomicLong(2L);
    l[1] = new AtomicLong(3L);
    assertTrue(e.supportsType(l.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "atomiclongaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "atomicLongAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, l, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertFalse(a.hasValue("1"));
    assertTrue(a.hasValue("2"));
    assertTrue(a.hasValue("3"));


    // Test the decodeField method with multiple values.
    assertNull(o.getAtomicLongAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getAtomicLongAF());
    assertEquals(o.getAtomicLongAF().length, 2);
    assertEquals(o.getAtomicLongAF()[0].longValue(), 2L);
    assertEquals(o.getAtomicLongAF()[1].longValue(), 3L);
  }



  /**
   * Provides test coverage for processing related to {@code AtomicLong} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAtomicLongGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getAtomicLongM");
    assertNotNull(m);

    AtomicLong l = new AtomicLong(1L);
    assertTrue(e.supportsType(l.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "atomiclongm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "atomicLongM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, l, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1"));
    assertFalse(a.hasValue("2"));
  }



  /**
   * Provides test coverage for processing related to {@code AtomicLong} array
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAtomicLongArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getAtomicLongAM");
    assertNotNull(m);

    AtomicLong[] l = new AtomicLong[2];
    l[0] = new AtomicLong(2L);
    l[1] = new AtomicLong(3L);
    assertTrue(e.supportsType(l.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "atomiclongam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "atomicLongAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, l, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertFalse(a.hasValue("1"));
    assertTrue(a.hasValue("2"));
    assertTrue(a.hasValue("3"));
  }



  /**
   * Provides test coverage for processing related to {@code AtomicLong} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAtomicLongSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setAtomicLongM",
         AtomicLong.class);
    assertNotNull(m);
    assertFalse(e.supportsMultipleValues(m));

    AtomicLong l = new AtomicLong(1L);
    assertTrue(e.supportsType(l.getClass()));


    // Test the invokeSetter method.
    assertNull(o.getAtomicLongM());

    e.invokeSetter(m, o, new Attribute("foo", "4"));

    assertNotNull(o.getAtomicLongM());
    assertEquals(o.getAtomicLongM().longValue(), 4L);
  }



  /**
   * Provides test coverage for processing related to {@code AtomicLong} array
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAtomicLongArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    AtomicLong[] l = new AtomicLong[2];
    l[0] = new AtomicLong(2L);
    l[1] = new AtomicLong(3L);
    assertTrue(e.supportsType(l.getClass()));

    Method m = o.getClass().getDeclaredMethod("setAtomicLongAM", l.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getAtomicLongAM());

    e.invokeSetter(m, o, new Attribute("foo", "4", "5"));

    assertNotNull(o.getAtomicLongAM());
    assertEquals(o.getAtomicLongAM().length, 2);
    assertEquals(o.getAtomicLongAM()[0].longValue(), 4L);
    assertEquals(o.getAtomicLongAM()[1].longValue(), 5L);
  }



  /**
   * Provides test coverage for processing related to {@code BigDecimal} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBigDecimalField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("bigDecimalF");
    assertNotNull(f);


    BigDecimal bd = new BigDecimal("1.234");
    assertTrue(e.supportsType(bd.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "bigdecimalf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "bigDecimalF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, bd, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1.234"));
    assertFalse(a.hasValue("5.678"));


    // Test the decodeField method with a single value.
    assertNull(o.getBigDecimalF());

    e.decodeField(f, o, a);

    assertNotNull(o.getBigDecimalF());
    assertEquals(o.getBigDecimalF().doubleValue(), bd.doubleValue());
  }



  /**
   * Provides test coverage for processing related to {@code BigDecimal} array
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBigDecimalArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("bigDecimalAF");
    assertNotNull(f);


    BigDecimal[] bd = new BigDecimal[2];
    bd[0] = new BigDecimal("1.234");
    bd[1] = new BigDecimal("5.678");
    assertTrue(e.supportsType(bd.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "bigdecimalaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "bigDecimalAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, bd, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("1.234"));
    assertTrue(a.hasValue("5.678"));
    assertFalse(a.hasValue("4.321"));


    // Test the decodeField method with multiple values.
    assertNull(o.getBigDecimalAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getBigDecimalAF());
    assertEquals(o.getBigDecimalAF().length, 2);
    assertEquals(o.getBigDecimalAF()[0].doubleValue(), bd[0].doubleValue());
    assertEquals(o.getBigDecimalAF()[1].doubleValue(), bd[1].doubleValue());
  }



  /**
   * Provides test coverage for processing related to {@code BigDecimal} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBigDecimalGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getBigDecimalM");
    assertNotNull(m);

    BigDecimal bd = new BigDecimal("1.234");
    assertTrue(e.supportsType(bd.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "bigdecimalm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "bigDecimalM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, bd, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1.234"));
    assertFalse(a.hasValue("5.678"));
  }



  /**
   * Provides test coverage for processing related to {@code BigDecimal} array
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBigDecimalArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getBigDecimalAM");
    assertNotNull(m);

    BigDecimal[] bd = new BigDecimal[2];
    bd[0] = new BigDecimal("1.234");
    bd[1] = new BigDecimal("5.678");
    assertTrue(e.supportsType(bd.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "bigdecimalam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "bigDecimalAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, bd, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("1.234"));
    assertTrue(a.hasValue("5.678"));
    assertFalse(a.hasValue("4.321"));
  }



  /**
   * Provides test coverage for processing related to {@code BigDecimal} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBigDecimalSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setBigDecimalM",
         BigDecimal.class);
    assertNotNull(m);

    BigDecimal bd = new BigDecimal("1.234");
    assertTrue(e.supportsType(bd.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getBigDecimalM());

    e.invokeSetter(m, o, new Attribute("foo", "1.234"));

    assertNotNull(o.getBigDecimalM());
    assertEquals(o.getBigDecimalM().doubleValue(), bd.doubleValue());
  }



  /**
   * Provides test coverage for processing related to {@code BigDecimal} array
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBigDecimalArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    BigDecimal[] bd = new BigDecimal[2];
    bd[0] = new BigDecimal("1.234");
    bd[1] = new BigDecimal("5.678");
    assertTrue(e.supportsType(bd.getClass()));

    Method m = o.getClass().getDeclaredMethod("setBigDecimalAM", bd.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getBigDecimalAM());

    e.invokeSetter(m, o, new Attribute("foo", "1.234", "5.678"));

    assertNotNull(o.getBigDecimalAM());
    assertEquals(o.getBigDecimalAM().length, 2);
    assertEquals(o.getBigDecimalAM()[0].doubleValue(), bd[0].doubleValue());
    assertEquals(o.getBigDecimalAM()[1].doubleValue(), bd[1].doubleValue());
  }



  /**
   * Provides test coverage for processing related to {@code BigInteger} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBigIntegerField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("bigIntegerF");
    assertNotNull(f);


    BigInteger i = new BigInteger("1");
    assertTrue(e.supportsType(i.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "bigintegerf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "bigIntegerF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, i, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1"));
    assertFalse(a.hasValue("2"));


    // Test the decodeField method with a single value.
    assertNull(o.getBigIntegerF());

    e.decodeField(f, o, a);

    assertNotNull(o.getBigIntegerF());
    assertEquals(o.getBigIntegerF().longValue(), 1L);
  }



  /**
   * Provides test coverage for processing related to {@code BigInteger} array
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBigIntegerArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("bigIntegerAF");
    assertNotNull(f);


    BigInteger[] i = new BigInteger[2];
    i[0] = new BigInteger("2");
    i[1] = new BigInteger("3");
    assertTrue(e.supportsType(i.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "bigintegeraf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "bigIntegerAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, i, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertFalse(a.hasValue("1"));
    assertTrue(a.hasValue("2"));
    assertTrue(a.hasValue("3"));


    // Test the decodeField method with multiple values.
    assertNull(o.getBigIntegerAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getBigIntegerAF());
    assertEquals(o.getBigIntegerAF().length, 2);
    assertEquals(o.getBigIntegerAF()[0].longValue(), 2L);
    assertEquals(o.getBigIntegerAF()[1].longValue(), 3L);
  }



  /**
   * Provides test coverage for processing related to {@code BigInteger} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBigIntegerGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getBigIntegerM");
    assertNotNull(m);

    BigInteger i = new BigInteger("1");
    assertTrue(e.supportsType(i.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "bigintegerm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "bigIntegerM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, i, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1"));
    assertFalse(a.hasValue("2"));
  }



  /**
   * Provides test coverage for processing related to {@code BigInteger} array
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBigIntegerArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getBigIntegerAM");
    assertNotNull(m);

    BigInteger[] i = new BigInteger[2];
    i[0] = new BigInteger("2");
    i[1] = new BigInteger("3");
    assertTrue(e.supportsType(i.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "bigintegeram-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "bigIntegerAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, i, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertFalse(a.hasValue("1"));
    assertTrue(a.hasValue("2"));
    assertTrue(a.hasValue("3"));
  }



  /**
   * Provides test coverage for processing related to {@code BigInteger} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBigIntegerSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setBigIntegerM",
         BigInteger.class);
    assertNotNull(m);

    BigInteger i = new BigInteger("1");
    assertTrue(e.supportsType(i.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getBigIntegerM());

    e.invokeSetter(m, o, new Attribute("foo", "4"));

    assertNotNull(o.getBigIntegerM());
    assertEquals(o.getBigIntegerM().longValue(), 4L);
  }



  /**
   * Provides test coverage for processing related to {@code BigInteger} array
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBigIntegerArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    BigInteger[] i = new BigInteger[2];
    i[0] = new BigInteger("2");
    i[1] = new BigInteger("3");
    assertTrue(e.supportsType(i.getClass()));

    Method m = o.getClass().getDeclaredMethod("setBigIntegerAM", i.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getBigIntegerAM());

    e.invokeSetter(m, o, new Attribute("foo", "4", "5"));

    assertNotNull(o.getBigIntegerAM());
    assertEquals(o.getBigIntegerAM().length, 2);
    assertEquals(o.getBigIntegerAM()[0].longValue(), 4L);
    assertEquals(o.getBigIntegerAM()[1].longValue(), 5L);
  }



  /**
   * Provides test coverage for processing related to {@code boolean} primitive
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanPrimitiveField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("booleanPF");
    assertNotNull(f);


    assertTrue(e.supportsType(Boolean.TYPE));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "booleanpf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "booleanPF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.7");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, true, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("TRUE"));


    // Test the decodeField method with a single value.
    assertFalse(o.getBooleanPF());

    e.decodeField(f, o, a);

    assertTrue(o.getBooleanPF());
  }



  /**
   * Provides test coverage for processing related to {@code boolean} primitive
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanPrimitiveArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("booleanPAF");
    assertNotNull(f);


    boolean[] b = new boolean[2];
    b[0] = true;
    b[1] = false;
    assertTrue(e.supportsType(b.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "booleanpaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "booleanPAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.7");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, b, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("TRUE"));
    assertTrue(a.hasValue("FALSE"));


    // Test the decodeField method with multiple values.
    assertNull(o.getBooleanPAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getBooleanPAF());
    assertEquals(o.getBooleanPAF().length, 2);
    assertTrue(o.getBooleanPAF()[0]);
    assertFalse(o.getBooleanPAF()[1]);
  }



  /**
   * Provides test coverage for processing related to {@code boolean} primitive
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanPrimitiveGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getBooleanPM");
    assertNotNull(m);

    assertTrue(e.supportsType(Boolean.TYPE));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "booleanpm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "booleanPM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.7");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, true, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("TRUE"));
    assertFalse(a.hasValue("FALSE"));
  }



  /**
   * Provides test coverage for processing related to {@code boolean} primitive
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanPrimitiveArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getBooleanPAM");
    assertNotNull(m);

    boolean[] b = new boolean[2];
    b[0] = true;
    b[1] = false;
    assertTrue(e.supportsType(b.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "booleanpam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "booleanPAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.7");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, b, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("TRUE"));
    assertTrue(a.hasValue("FALSE"));
  }



  /**
   * Provides test coverage for processing related to {@code boolean} primitive
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanPrimitiveSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setBooleanPM",
         Boolean.TYPE);
    assertNotNull(m);

    boolean b = true;
    assertTrue(e.supportsType(Boolean.TYPE));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertFalse(o.getBooleanPM());

    e.invokeSetter(m, o, new Attribute("foo", "TRUE"));

    assertTrue(o.getBooleanPM());
  }



  /**
   * Provides test coverage for processing related to {@code boolean} primitive
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanPrimitiveArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    boolean[] b = new boolean[2];
    b[0] = true;
    b[1] = false;
    assertTrue(e.supportsType(b.getClass()));

    Method m = o.getClass().getDeclaredMethod("setBooleanPAM", b.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getBooleanPAM());

    e.invokeSetter(m, o, new Attribute("foo", "TRUE", "FALSE"));

    assertNotNull(o.getBooleanPAM());
    assertEquals(o.getBooleanPAM().length, 2);
    assertTrue(o.getBooleanPAM()[0]);
    assertFalse(o.getBooleanPAM()[1]);
  }



  /**
   * Provides test coverage for processing related to {@code Boolean} object
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanObjectField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("booleanOF");
    assertNotNull(f);


    assertTrue(e.supportsType(Boolean.class));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "booleanof-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "booleanOF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.7");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, Boolean.FALSE, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("FALSE"));


    // Test the decodeField method with a single value.
    assertNull(o.getBooleanOF());

    e.decodeField(f, o, a);

    assertNotNull(o.getBooleanOF());
    assertEquals(o.getBooleanOF(), Boolean.FALSE);
  }



  /**
   * Provides test coverage for processing related to {@code Boolean} object
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanObjectArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("booleanOAF");
    assertNotNull(f);


    Boolean[] b = new Boolean[2];
    b[0] = Boolean.TRUE;
    b[1] = Boolean.FALSE;
    assertTrue(e.supportsType(b.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "booleanoaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "booleanOAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.7");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, b, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("TRUE"));
    assertTrue(a.hasValue("FALSE"));


    // Test the decodeField method with multiple values.
    assertNull(o.getBooleanOAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getBooleanOAF());
    assertEquals(o.getBooleanOAF().length, 2);
    assertEquals(o.getBooleanOAF()[0], Boolean.TRUE);
    assertEquals(o.getBooleanOAF()[1], Boolean.FALSE);
  }



  /**
   * Provides test coverage for processing related to {@code Boolean} object
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanObjectGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getBooleanOM");
    assertNotNull(m);

    assertTrue(e.supportsType(Boolean.class));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "booleanom-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "booleanOM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.7");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, Boolean.TRUE, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("TRUE"));
    assertFalse(a.hasValue("FALSE"));
  }



  /**
   * Provides test coverage for processing related to {@code Boolean} object
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanObjectArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getBooleanOAM");
    assertNotNull(m);

    Boolean[] b = new Boolean[2];
    b[0] = Boolean.TRUE;
    b[1] = Boolean.FALSE;
    assertTrue(e.supportsType(b.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "booleanoam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "booleanOAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.7");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, b, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("TRUE"));
    assertTrue(a.hasValue("FALSE"));
  }



  /**
   * Provides test coverage for processing related to {@code Boolean} object
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanObjectSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setBooleanOM", Boolean.class);
    assertNotNull(m);

    boolean b = true;
    assertTrue(e.supportsType(Boolean.class));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getBooleanOM());

    e.invokeSetter(m, o, new Attribute("foo", "TRUE"));

    assertNotNull(o.getBooleanOM());
    assertEquals(o.getBooleanOM(), Boolean.TRUE);
  }



  /**
   * Provides test coverage for processing related to {@code Boolean} object
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanObjectArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Boolean[] b = new Boolean[2];
    b[0] = Boolean.TRUE;
    b[1] = Boolean.TRUE;
    assertTrue(e.supportsType(b.getClass()));

    Method m = o.getClass().getDeclaredMethod("setBooleanOAM", b.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getBooleanOAM());

    e.invokeSetter(m, o, new Attribute("foo", "TRUE", "FALSE"));

    assertNotNull(o.getBooleanOAM());
    assertEquals(o.getBooleanOAM().length, 2);
    assertEquals(o.getBooleanOAM()[0], Boolean.TRUE);
    assertEquals(o.getBooleanOAM()[1], Boolean.FALSE);
  }



  /**
   * Provides test coverage for processing related to {@code byte} array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testByteArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("bytePAF");
    assertNotNull(f);


    byte[] b = getBytes("foo");
    assertTrue(e.supportsType(b.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "bytepaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "bytePAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.40");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, b, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("foo"));
    assertFalse(a.hasValue("bar"));


    // Test the decodeField method with a single value.
    assertNull(o.getBytePAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getBytePAF());
    assertTrue(Arrays.equals(o.getBytePAF(), getBytes("foo")));
  }



  /**
   * Provides test coverage for processing related to two-dimensional
   * {@code byte} array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTwoDimensionalByteArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("bytePAAF");
    assertNotNull(f);


    byte[][] b = new byte[2][];
    b[0] = getBytes("foo");
    b[1] = getBytes("bar");
    assertTrue(e.supportsType(b.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "bytepaaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "bytePAAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.40");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, b, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertFalse(a.hasValue("1"));
    assertTrue(a.hasValue("foo"));
    assertTrue(a.hasValue("bar"));


    // Test the decodeField method with multiple values.
    assertNull(o.getBytePAAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getBytePAAF());
    assertEquals(o.getBytePAAF().length, 2);
    assertTrue(Arrays.equals(o.getBytePAAF()[0], getBytes("foo")));
    assertTrue(Arrays.equals(o.getBytePAAF()[1], getBytes("bar")));
  }



  /**
   * Provides test coverage for processing related to {@code byte} array getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testByteArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getBytePAM");
    assertNotNull(m);

    byte[] b = getBytes("foo");
    assertTrue(e.supportsType(b.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "bytepam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "bytePAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.40");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, b, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("foo"));
    assertFalse(a.hasValue("bar"));
  }



  /**
   * Provides test coverage for processing related to two-dimensional
   * {@code byte} array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTwoDimensionalByteArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getBytePAAM");
    assertNotNull(m);

    byte[][] b = new byte[2][];
    b[0] = getBytes("foo");
    b[1] = getBytes("bar");
    assertTrue(e.supportsType(b.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "bytepaam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "bytePAAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.40");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, b, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("foo"));
    assertTrue(a.hasValue("bar"));
  }



  /**
   * Provides test coverage for processing related to {@code byte} array setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testByteArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    byte[] b = getBytes("foo");
    Method m = o.getClass().getDeclaredMethod("setBytePAM", b.getClass());
    assertNotNull(m);

    assertTrue(e.supportsType(b.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getBytePAM());

    e.invokeSetter(m, o, new Attribute("foo", "bar"));

    assertNotNull(o.getBytePAM());
    assertTrue(Arrays.equals(o.getBytePAM(), getBytes("bar")));
  }



  /**
   * Provides test coverage for processing related to two-dimensional
   * {@code byte} array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTwoDimensionalByteArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    byte[][] b = new byte[2][];
    b[0] = getBytes("foo");
    b[1] = getBytes("bar");
    assertTrue(e.supportsType(b.getClass()));

    Method m = o.getClass().getDeclaredMethod("setBytePAAM", b.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getBytePAAM());

    e.invokeSetter(m, o, new Attribute("foo", "bar", "baz"));

    assertNotNull(o.getBytePAAM());
    assertEquals(o.getBytePAAM().length, 2);
    assertTrue(Arrays.equals(o.getBytePAAM()[0], getBytes("bar")));
    assertTrue(Arrays.equals(o.getBytePAAM()[1], getBytes("baz")));
  }



  /**
   * Provides test coverage for processing related to {@code char} array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCharArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("charPAF");
    assertNotNull(f);


    char[] c = "foo".toCharArray();
    assertTrue(e.supportsType(c.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "charpaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "charPAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, c, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("foo"));
    assertFalse(a.hasValue("bar"));


    // Test the decodeField method with a single value.
    assertNull(o.getCharPAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getCharPAF());
    assertTrue(Arrays.equals(o.getCharPAF(), "foo".toCharArray()));
  }



  /**
   * Provides test coverage for processing related to two-dimensional
   * {@code char} array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTwoDimensionalCharArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("charPAAF");
    assertNotNull(f);


    char[][] c = new char[2][];
    c[0] = "foo".toCharArray();
    c[1] = "bar".toCharArray();
    assertTrue(e.supportsType(c.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "charpaaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "charPAAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, c, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertFalse(a.hasValue("1"));
    assertTrue(a.hasValue("foo"));
    assertTrue(a.hasValue("bar"));


    // Test the decodeField method with multiple values.
    assertNull(o.getCharPAAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getCharPAAF());
    assertEquals(o.getCharPAAF().length, 2);
    assertTrue(Arrays.equals(o.getCharPAAF()[0], "foo".toCharArray()));
    assertTrue(Arrays.equals(o.getCharPAAF()[1], "bar".toCharArray()));
  }



  /**
   * Provides test coverage for processing related to {@code char} array getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCharArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getCharPAM");
    assertNotNull(m);

    char[] c = "foo".toCharArray();
    assertTrue(e.supportsType(c.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "charpam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "charPAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, c, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("foo"));
    assertFalse(a.hasValue("bar"));
  }



  /**
   * Provides test coverage for processing related to two-dimensional
   * {@code char} array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTwoDimensionalCharArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getCharPAAM");
    assertNotNull(m);

    char[][] c = new char[2][];
    c[0] = "foo".toCharArray();
    c[1] = "bar".toCharArray();
    assertTrue(e.supportsType(c.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "charpaam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "charPAAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, c, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("foo"));
    assertTrue(a.hasValue("bar"));
  }



  /**
   * Provides test coverage for processing related to {@code char} array setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCharArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    char[] c = "foo".toCharArray();
    Method m = o.getClass().getDeclaredMethod("setCharPAM", c.getClass());
    assertNotNull(m);
    assertFalse(e.supportsMultipleValues(m));

    assertTrue(e.supportsType(c.getClass()));


    // Test the invokeSetter method.
    assertNull(o.getCharPAM());

    e.invokeSetter(m, o, new Attribute("foo", "bar"));

    assertNotNull(o.getCharPAM());
    assertTrue(Arrays.equals(o.getCharPAM(), "bar".toCharArray()));
  }



  /**
   * Provides test coverage for processing related to two-dimensional
   * {@code char} array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTwoDimensionalCharArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    char[][] c = new char[2][];
    c[0] = "foo".toCharArray();
    c[1] = "bar".toCharArray();
    assertTrue(e.supportsType(c.getClass()));

    Method m = o.getClass().getDeclaredMethod("setCharPAAM", c.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getCharPAAM());

    e.invokeSetter(m, o, new Attribute("foo", "bar", "baz"));

    assertNotNull(o.getCharPAAM());
    assertEquals(o.getCharPAAM().length, 2);
    assertTrue(Arrays.equals(o.getCharPAAM()[0], "bar".toCharArray()));
    assertTrue(Arrays.equals(o.getCharPAAM()[1], "baz".toCharArray()));
  }



  /**
   * Provides test coverage for processing related to {@code Date} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDateField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("dateF");
    assertNotNull(f);


    Date date = new Date();
    assertTrue(e.supportsType(date.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "datef-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "dateF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.24");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, date, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue(encodeGeneralizedTime(date)));


    // Test the decodeField method with a single value.
    assertNull(o.getDateF());

    e.decodeField(f, o, a);

    assertNotNull(o.getDateF());
    assertEquals(o.getDateF().getTime(), date.getTime());
  }



  /**
   * Provides test coverage for processing related to {@code Date} array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDateArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("dateAF");
    assertNotNull(f);


    Date[] dates = new Date[2];
    dates[0] = new Date();
    dates[1] = new Date(dates[0].getTime() + 1234L);
    assertTrue(e.supportsType(dates.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "dateaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "dateAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.24");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, dates, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue(encodeGeneralizedTime(dates[0])));
    assertTrue(a.hasValue(encodeGeneralizedTime(dates[1])));


    // Test the decodeField method with multiple values.
    assertNull(o.getDateAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getDateAF());
    assertEquals(o.getDateAF().length, 2);
    assertEquals(o.getDateAF()[0].getTime(), dates[0].getTime());
    assertEquals(o.getDateAF()[1].getTime(), dates[1].getTime());
  }



  /**
   * Provides test coverage for processing related to {@code Date} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDateGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getDateM");
    assertNotNull(m);

    Date date = new Date();
    assertTrue(e.supportsType(date.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "datem-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "dateM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.24");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, date, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue(encodeGeneralizedTime(date)));
  }



  /**
   * Provides test coverage for processing related to {@code Date} array getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDateArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getDateAM");
    assertNotNull(m);

    Date[] dates = new Date[2];
    dates[0] = new Date();
    dates[1] = new Date(dates[0].getTime() + 1234L);
    assertTrue(e.supportsType(dates.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "dateam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "dateAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.24");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, dates, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue(encodeGeneralizedTime(dates[0])));
    assertTrue(a.hasValue(encodeGeneralizedTime(dates[1])));
  }



  /**
   * Provides test coverage for processing related to {@code Date} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDateSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setDateM", Date.class);
    assertNotNull(m);

    Date date = new Date();
    assertTrue(e.supportsType(date.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getDateM());

    e.invokeSetter(m, o, new Attribute("foo", encodeGeneralizedTime(date)));

    assertNotNull(o.getDateM());
    assertEquals(o.getDateM().getTime(), date.getTime());
  }



  /**
   * Provides test coverage for processing related to {@code Date} array setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDateArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Date[] dates = new Date[2];
    dates[0] = new Date();
    dates[1] = new Date(dates[0].getTime() + 1234L);
    assertTrue(e.supportsType(dates.getClass()));

    Method m = o.getClass().getDeclaredMethod("setDateAM", dates.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getDateAM());

    e.invokeSetter(m, o, new Attribute("foo", encodeGeneralizedTime(dates[0]),
         encodeGeneralizedTime(dates[1])));

    assertNotNull(o.getDateAM());
    assertEquals(o.getDateAM().length, 2);
    assertEquals(o.getDateAM()[0].getTime(), dates[0].getTime());
    assertEquals(o.getDateAM()[1].getTime(), dates[1].getTime());
  }



  /**
   * Provides test coverage for processing related to {@code DN} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("dnF");
    assertNotNull(f);


    DN dn = new DN("dc=example,dc=com");
    assertTrue(e.supportsType(dn.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "dnf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "dnF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.12");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, dn, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("dc=example,dc=com"));


    // Test the decodeField method with a single value.
    assertNull(o.getDNF());

    e.decodeField(f, o, a);

    assertNotNull(o.getDNF());
    assertEquals(o.getDNF(), new DN("dc=example,dc=com"));
  }



  /**
   * Provides test coverage for processing related to {@code DN} array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("dnAF");
    assertNotNull(f);


    DN[] dns = new DN[2];
    dns[0] = new DN("dc=example,dc=com");
    dns[1] = new DN("o=example.com");
    assertTrue(e.supportsType(dns.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "dnaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "dnAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.12");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, dns, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("dc=example,dc=com"));
    assertTrue(a.hasValue("o=example.com"));


    // Test the decodeField method with multiple values.
    assertNull(o.getDNAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getDNAF());
    assertEquals(o.getDNAF().length, 2);
    assertEquals(o.getDNAF()[0], new DN("dc=example,dc=com"));
    assertEquals(o.getDNAF()[1], new DN("o=example.com"));
  }



  /**
   * Provides test coverage for processing related to {@code DN} getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getDNM");
    assertNotNull(m);

    DN dn = new DN("dc=example,dc=com");
    assertTrue(e.supportsType(dn.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "dnm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "dnM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.12");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, dn, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("dc=example,dc=com"));
  }



  /**
   * Provides test coverage for processing related to {@code DN} array getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getDNAM");
    assertNotNull(m);

    DN[] dns = new DN[2];
    dns[0] = new DN("dc=example,dc=com");
    dns[1] = new DN("o=example.com");
    assertTrue(e.supportsType(dns.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "dnam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "dnAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.12");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, dns, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("dc=example,dc=com"));
    assertTrue(a.hasValue("o=example.com"));
  }



  /**
   * Provides test coverage for processing related to {@code DN} setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setDNM", DN.class);
    assertNotNull(m);

    DN dn = new DN("dc=example,dc=com");
    assertTrue(e.supportsType(dn.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getDNM());

    e.invokeSetter(m, o, new Attribute("foo", "dc=example,dc=com"));

    assertNotNull(o.getDNM());
    assertEquals(o.getDNM(), new DN("dc=example,dc=com"));
  }



  /**
   * Provides test coverage for processing related to {@code DN} array setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    DN[] dns = new DN[2];
    dns[0] = new DN("dc=example,dc=com");
    dns[1] = new DN("o=example.com");
    assertTrue(e.supportsType(dns.getClass()));

    Method m = o.getClass().getDeclaredMethod("setDNAM", dns.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getDNAM());

    e.invokeSetter(m, o, new Attribute("foo", "dc=example,dc=com",
         "o=example.com"));

    assertNotNull(o.getDNAM());
    assertEquals(o.getDNAM().length, 2);
    assertEquals(o.getDNAM()[0], new DN("dc=example,dc=com"));
    assertEquals(o.getDNAM()[1], new DN("o=example.com"));
  }



  /**
   * Provides test coverage for processing related to {@code double} primitive
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoublePrimitiveField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("doublePF");
    assertNotNull(f);


    assertTrue(e.supportsType(Double.TYPE));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "doublepf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "doublePF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, 1.25d, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1.25"));


    // Test the decodeField method with a single value.
    assertEquals(o.getDoublePF(), 0.0d);

    e.decodeField(f, o, a);

    assertEquals(o.getDoublePF(), 1.25d);
  }



  /**
   * Provides test coverage for processing related to {@code double} primitive
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoublePrimitiveArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("doublePAF");
    assertNotNull(f);


    double[] doubles = new double[2];
    doubles[0] = 1.25d;
    doubles[1] = 2.5d;
    assertTrue(e.supportsType(doubles.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "doublepaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "doublePAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, doubles, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("1.25"));
    assertTrue(a.hasValue("2.5"));


    // Test the decodeField method with multiple values.
    assertNull(o.getDoublePAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getDoublePAF());
    assertEquals(o.getDoublePAF().length, 2);
    assertEquals(o.getDoublePAF()[0], 1.25d);
    assertEquals(o.getDoublePAF()[1], 2.5d);
  }



  /**
   * Provides test coverage for processing related to {@code double} primitive
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoublePrimitiveGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getDoublePM");
    assertNotNull(m);

    assertTrue(e.supportsType(Double.TYPE));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "doublepm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "doublePM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, 1.25d, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1.25"));
  }



  /**
   * Provides test coverage for processing related to {@code double} primitive
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoublePrimitiveArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getDoublePAM");
    assertNotNull(m);

    double[] doubles = new double[2];
    doubles[0] = 1.25d;
    doubles[1] = 2.5d;
    assertTrue(e.supportsType(doubles.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "doublepam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "doublePAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, doubles, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("1.25"));
    assertTrue(a.hasValue("2.5"));
  }



  /**
   * Provides test coverage for processing related to {@code double} primitive
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoublePrimitiveSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setDoublePM", Double.TYPE);
    assertNotNull(m);

    assertTrue(e.supportsType(Double.TYPE));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertEquals(o.getDoublePM(), 0.0d);

    e.invokeSetter(m, o, new Attribute("foo", "1.25"));

    assertEquals(o.getDoublePM(), 1.25d);
  }



  /**
   * Provides test coverage for processing related to {@code double} primitive
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoublePrimitiveArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    double[] doubles = new double[2];
    doubles[0] = 1.25d;
    doubles[1] = 2.5d;
    assertTrue(e.supportsType(doubles.getClass()));

    Method m = o.getClass().getDeclaredMethod("setDoublePAM",
         doubles.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getDoublePAM());

    e.invokeSetter(m, o, new Attribute("foo", "1.25", "2.5"));

    assertNotNull(o.getDoublePAM());
    assertEquals(o.getDoublePAM().length, 2);
    assertEquals(o.getDoublePAM()[0], 1.25d);
    assertEquals(o.getDoublePAM()[1], 2.5d);
  }



  /**
   * Provides test coverage for processing related to {@code Double} object
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoubleObjectField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("doubleOF");
    assertNotNull(f);


    assertTrue(e.supportsType(Double.class));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "doubleof-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "doubleOF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, Double.valueOf(1.25d), "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1.25"));


    // Test the decodeField method with a single value.
    assertNull(o.getDoubleOF());

    e.decodeField(f, o, a);

    assertNotNull(o.getDoubleOF());
    assertEquals(o.getDoubleOF().doubleValue(), 1.25d);
  }



  /**
   * Provides test coverage for processing related to {@code Double} object
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoubleObjectArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("doubleOAF");
    assertNotNull(f);


    Double[] doubles = new Double[2];
    doubles[0] = Double.valueOf(1.25d);
    doubles[1] = Double.valueOf(2.5d);
    assertTrue(e.supportsType(doubles.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "doubleoaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "doubleOAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, doubles, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("1.25"));
    assertTrue(a.hasValue("2.5"));


    // Test the decodeField method with multiple values.
    assertNull(o.getDoubleOAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getDoubleOAF());
    assertEquals(o.getDoubleOAF().length, 2);
    assertEquals(o.getDoubleOAF()[0], Double.valueOf(1.25d));
    assertEquals(o.getDoubleOAF()[1], Double.valueOf(2.5d));
  }



  /**
   * Provides test coverage for processing related to {@code Double} object
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoubleObjectGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getDoubleOM");
    assertNotNull(m);

    assertTrue(e.supportsType(Double.class));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "doubleom-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "doubleOM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, Double.valueOf(1.25d), "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1.25"));
  }



  /**
   * Provides test coverage for processing related to {@code Double} object
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoubleObjectArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getDoubleOAM");
    assertNotNull(m);

    Double[] doubles = new Double[2];
    doubles[0] = Double.valueOf(1.25d);
    doubles[1] = Double.valueOf(2.5d);
    assertTrue(e.supportsType(doubles.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "doubleoam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "doubleOAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, doubles, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("1.25"));
    assertTrue(a.hasValue("2.5"));
  }



  /**
   * Provides test coverage for processing related to {@code Double} object
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoubleObjectSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setDoubleOM", Double.class);
    assertNotNull(m);

    assertTrue(e.supportsType(Double.class));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getDoubleOM());

    e.invokeSetter(m, o, new Attribute("foo", "1.25"));

    assertNotNull(o.getDoubleOM());
    assertEquals(o.getDoubleOM(), Double.valueOf(1.25d));
  }



  /**
   * Provides test coverage for processing related to {@code Double} object
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoubleObjectArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Double[] doubles = new Double[2];
    doubles[0] = Double.valueOf(1.25d);
    doubles[1] = Double.valueOf(2.5d);
    assertTrue(e.supportsType(doubles.getClass()));

    Method m = o.getClass().getDeclaredMethod("setDoubleOAM",
         doubles.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getDoubleOAM());

    e.invokeSetter(m, o, new Attribute("foo", "1.25", "2.5"));

    assertNotNull(o.getDoubleOAM());
    assertEquals(o.getDoubleOAM().length, 2);
    assertEquals(o.getDoubleOAM()[0], Double.valueOf(1.25d));
    assertEquals(o.getDoubleOAM()[1], Double.valueOf(2.5d));
  }



  /**
   * Provides test coverage for processing related to {@code Filter} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("filterF");
    assertNotNull(f);


    Filter filter = Filter.create("(objectClass=*)");
    assertTrue(e.supportsType(filter.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "filterf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "filterF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, filter, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("(objectClass=*)"));


    // Test the decodeField method with a single value.
    assertNull(o.getFilterF());

    e.decodeField(f, o, a);

    assertNotNull(o.getFilterF());
    assertEquals(o.getFilterF(), Filter.createPresenceFilter("objectClass"));
  }



  /**
   * Provides test coverage for processing related to {@code Filter} array
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("filterAF");
    assertNotNull(f);


    Filter[] filters = new Filter[2];
    filters[0] = Filter.createEqualityFilter("a", "b");
    filters[1] = Filter.createEqualityFilter("c", "d");
    assertTrue(e.supportsType(filters.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "filteraf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "filterAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, filters, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("(a=b)"));
    assertTrue(a.hasValue("(c=d)"));


    // Test the decodeField method with multiple values.
    assertNull(o.getFilterAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getFilterAF());
    assertEquals(o.getFilterAF().length, 2);
    assertEquals(o.getFilterAF()[0], filters[0]);
    assertEquals(o.getFilterAF()[1], filters[1]);
  }



  /**
   * Provides test coverage for processing related to {@code Filter} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getFilterM");
    assertNotNull(m);

    Filter filter = Filter.create("(objectClass=*)");
    assertTrue(e.supportsType(filter.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "filterm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "filterM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, filter, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("(objectClass=*)"));
  }



  /**
   * Provides test coverage for processing related to {@code Filter} array
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getFilterAM");
    assertNotNull(m);

    Filter[] filters = new Filter[2];
    filters[0] = Filter.createEqualityFilter("a", "b");
    filters[1] = Filter.createEqualityFilter("c", "d");
    assertTrue(e.supportsType(filters.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "filteram-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "filterAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, filters, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("(a=b)"));
    assertTrue(a.hasValue("(c=d)"));
  }



  /**
   * Provides test coverage for processing related to {@code Filter} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setFilterM", Filter.class);
    assertNotNull(m);

    Filter filter = Filter.create("(objectClass=*)");
    assertTrue(e.supportsType(filter.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getFilterM());

    e.invokeSetter(m, o, new Attribute("foo", "(objectClass=*)"));

    assertNotNull(o.getFilterM());
    assertEquals(o.getFilterM(), filter);
  }



  /**
   * Provides test coverage for processing related to {@code Filter} array
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Filter[] filters = new Filter[2];
    filters[0] = Filter.createEqualityFilter("a", "b");
    filters[1] = Filter.createEqualityFilter("c", "d");
    assertTrue(e.supportsType(filters.getClass()));

    Method m = o.getClass().getDeclaredMethod("setFilterAM",
         filters.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getFilterAM());

    e.invokeSetter(m, o, new Attribute("foo", "(a=b)", "(c=d)"));

    assertNotNull(o.getFilterAM());
    assertEquals(o.getFilterAM().length, 2);
    assertEquals(o.getFilterAM()[0], filters[0]);
    assertEquals(o.getFilterAM()[1], filters[1]);
  }



  /**
   * Provides test coverage for processing related to {@code FilterUsage}
   * fields.  This will cover functionality for all enum types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterUsageField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("filterUsageF");
    assertNotNull(f);


    FilterUsage filterUsage = FilterUsage.ALWAYS_ALLOWED;
    assertTrue(e.supportsType(filterUsage.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "filterusagef-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "filterUsageF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, filterUsage, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("ALWAYS_ALLOWED"));


    // Test the decodeField method with a single value.
    assertNull(o.getFilterUsageF());

    e.decodeField(f, o, a);

    assertNotNull(o.getFilterUsageF());
    assertEquals(o.getFilterUsageF(), FilterUsage.ALWAYS_ALLOWED);
  }



  /**
   * Provides test coverage for processing related to {@code FilterUsage} array
   * fields.  This will cover functionality for all enum types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterUsageArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("filterUsageAF");
    assertNotNull(f);


    FilterUsage[] filterUsages = new FilterUsage[2];
    filterUsages[0] = FilterUsage.CONDITIONALLY_ALLOWED;
    filterUsages[1] = FilterUsage.EXCLUDED;
    assertTrue(e.supportsType(filterUsages.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "filterusageaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "filterUsageAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, filterUsages, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("CONDITIONALLY_ALLOWED"));
    assertTrue(a.hasValue("EXCLUDED"));


    // Test the decodeField method with multiple values.
    assertNull(o.getFilterUsageAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getFilterUsageAF());
    assertEquals(o.getFilterUsageAF().length, 2);
    assertEquals(o.getFilterUsageAF()[0], filterUsages[0]);
    assertEquals(o.getFilterUsageAF()[1], filterUsages[1]);
  }



  /**
   * Provides test coverage for processing related to {@code FilterUsage} getter
   * methods.  This will cover functionality for all enum types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterUsageGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getFilterUsageM");
    assertNotNull(m);

    FilterUsage filterUsage = FilterUsage.ALWAYS_ALLOWED;
    assertTrue(e.supportsType(filterUsage.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "filterusagem-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "filterUsageM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, filterUsage, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("ALWAYS_ALLOWED"));
  }



  /**
   * Provides test coverage for processing related to {@code FilterUsage} array
   * getter methods.  This will cover functionality for all enum types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterUsageArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getFilterUsageAM");
    assertNotNull(m);

    FilterUsage[] filterUsages = new FilterUsage[2];
    filterUsages[0] = FilterUsage.CONDITIONALLY_ALLOWED;
    filterUsages[1] = FilterUsage.EXCLUDED;
    assertTrue(e.supportsType(filterUsages.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "filterusageam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "filterUsageAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, filterUsages, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("CONDITIONALLY_ALLOWED"));
    assertTrue(a.hasValue("EXCLUDED"));
  }



  /**
   * Provides test coverage for processing related to {@code FilterUsage} setter
   * methods.  This will cover functionality for all enum types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterUsageSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setFilterUsageM",
         FilterUsage.class);
    assertNotNull(m);

    FilterUsage filterUsage = FilterUsage.ALWAYS_ALLOWED;
    assertTrue(e.supportsType(filterUsage.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getFilterUsageM());

    e.invokeSetter(m, o, new Attribute("foo", "ALWAYS_ALLOWED"));

    assertNotNull(o.getFilterUsageM());
    assertEquals(o.getFilterUsageM(), filterUsage);
  }



  /**
   * Provides test coverage for processing related to {@code FilterUsage} array
   * setter methods.  This will cover functionality for all enum types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterUsageArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    FilterUsage[] filterUsages = new FilterUsage[2];
    filterUsages[0] = FilterUsage.CONDITIONALLY_ALLOWED;
    filterUsages[1] = FilterUsage.EXCLUDED;
    assertTrue(e.supportsType(filterUsages.getClass()));

    Method m = o.getClass().getDeclaredMethod("setFilterUsageAM",
         filterUsages.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getFilterUsageAM());

    e.invokeSetter(m, o, new Attribute("foo", "CONDITIONALLY_ALLOWED",
         "EXCLUDED"));

    assertNotNull(o.getFilterUsageAM());
    assertEquals(o.getFilterUsageAM().length, 2);
    assertEquals(o.getFilterUsageAM()[0], filterUsages[0]);
    assertEquals(o.getFilterUsageAM()[1], filterUsages[1]);
  }



  /**
   * Provides test coverage for processing related to {@code float} primitive
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFloatPrimitiveField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("floatPF");
    assertNotNull(f);


    assertTrue(e.supportsType(Float.TYPE));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "floatpf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "floatPF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, 1.25f, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1.25"));


    // Test the decodeField method with a single value.
    assertEquals(o.getFloatPF(), 0.0f);

    e.decodeField(f, o, a);

    assertEquals(o.getFloatPF(), 1.25f);
  }



  /**
   * Provides test coverage for processing related to {@code float} primitive
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFloatPrimitiveArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("floatPAF");
    assertNotNull(f);


    float[] floats = new float[2];
    floats[0] = 1.25f;
    floats[1] = 2.5f;
    assertTrue(e.supportsType(floats.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "floatpaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "floatPAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, floats, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("1.25"));
    assertTrue(a.hasValue("2.5"));


    // Test the decodeField method with multiple values.
    assertNull(o.getFloatPAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getFloatPAF());
    assertEquals(o.getFloatPAF().length, 2);
    assertEquals(o.getFloatPAF()[0], 1.25f);
    assertEquals(o.getFloatPAF()[1], 2.5f);
  }



  /**
   * Provides test coverage for processing related to {@code float} primitive
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFloatPrimitiveGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getFloatPM");
    assertNotNull(m);

    assertTrue(e.supportsType(Float.TYPE));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "floatpm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "floatPM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, 1.25f, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1.25"));
  }



  /**
   * Provides test coverage for processing related to {@code float} primitive
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFloatPrimitiveArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getFloatPAM");
    assertNotNull(m);

    float[] floats = new float[2];
    floats[0] = 1.25f;
    floats[1] = 2.5f;
    assertTrue(e.supportsType(floats.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "floatpam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "floatPAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, floats, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("1.25"));
    assertTrue(a.hasValue("2.5"));
  }



  /**
   * Provides test coverage for processing related to {@code float} primitive
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFloatPrimitiveSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setFloatPM", Float.TYPE);
    assertNotNull(m);

    assertTrue(e.supportsType(Float.TYPE));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertEquals(o.getFloatPM(), 0.0f);

    e.invokeSetter(m, o, new Attribute("foo", "1.25"));

    assertEquals(o.getFloatPM(), 1.25f);
  }



  /**
   * Provides test coverage for processing related to {@code float} primitive
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFloatPrimitiveArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    float[] floats = new float[2];
    floats[0] = 1.25f;
    floats[1] = 2.5f;
    assertTrue(e.supportsType(floats.getClass()));

    Method m = o.getClass().getDeclaredMethod("setFloatPAM", floats.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getFloatPAM());

    e.invokeSetter(m, o, new Attribute("foo", "1.25", "2.5"));

    assertNotNull(o.getFloatPAM());
    assertEquals(o.getFloatPAM().length, 2);
    assertEquals(o.getFloatPAM()[0], 1.25f);
    assertEquals(o.getFloatPAM()[1], 2.5f);
  }



  /**
   * Provides test coverage for processing related to {@code Float} object
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFloatObjectField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("floatOF");
    assertNotNull(f);


    assertTrue(e.supportsType(Float.class));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "floatof-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "floatOF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, Float.valueOf(1.25f), "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1.25"));


    // Test the decodeField method with a single value.
    assertNull(o.getFloatOF());

    e.decodeField(f, o, a);

    assertNotNull(o.getFloatOF());
    assertEquals(o.getFloatOF().floatValue(), 1.25f);
  }



  /**
   * Provides test coverage for processing related to {@code FLoat} object
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFloatObjectArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("floatOAF");
    assertNotNull(f);


    Float[] floats = new Float[2];
    floats[0] = Float.valueOf(1.25f);
    floats[1] = Float.valueOf(2.5f);
    assertTrue(e.supportsType(floats.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "floatoaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "floatOAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, floats, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("1.25"));
    assertTrue(a.hasValue("2.5"));


    // Test the decodeField method with multiple values.
    assertNull(o.getFloatOAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getFloatOAF());
    assertEquals(o.getFloatOAF().length, 2);
    assertEquals(o.getFloatOAF()[0], Float.valueOf(1.25f));
    assertEquals(o.getFloatOAF()[1], Float.valueOf(2.5f));
  }



  /**
   * Provides test coverage for processing related to {@code Float} object
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFloatObjectGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getFloatOM");
    assertNotNull(m);

    assertTrue(e.supportsType(Float.class));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "floatom-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "floatOM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, Float.valueOf(1.25f), "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("1.25"));
  }



  /**
   * Provides test coverage for processing related to {@code Float} object
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFloatObjectArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getFloatOAM");
    assertNotNull(m);

    Float[] floats = new Float[2];
    floats[0] = Float.valueOf(1.25f);
    floats[1] = Float.valueOf(2.5f);
    assertTrue(e.supportsType(floats.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "floatoam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "floatOAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, floats, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("1.25"));
    assertTrue(a.hasValue("2.5"));
  }



  /**
   * Provides test coverage for processing related to {@code Float} object
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFloatObjectSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setFloatOM", Float.class);
    assertNotNull(m);

    assertTrue(e.supportsType(Float.class));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getFloatOM());

    e.invokeSetter(m, o, new Attribute("foo", "1.25"));

    assertNotNull(o.getFloatOM());
    assertEquals(o.getFloatOM(), Float.valueOf(1.25f));
  }



  /**
   * Provides test coverage for processing related to {@code Float} object
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFloatObjectArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Float[] floats = new Float[2];
    floats[0] = Float.valueOf(1.25f);
    floats[1] = Float.valueOf(2.5f);
    assertTrue(e.supportsType(floats.getClass()));

    Method m = o.getClass().getDeclaredMethod("setFloatOAM", floats.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getFloatOAM());

    e.invokeSetter(m, o, new Attribute("foo", "1.25", "2.5"));

    assertNotNull(o.getFloatOAM());
    assertEquals(o.getFloatOAM().length, 2);
    assertEquals(o.getFloatOAM()[0], Float.valueOf(1.25f));
    assertEquals(o.getFloatOAM()[1], Float.valueOf(2.5f));
  }



  /**
   * Provides test coverage for processing related to {@code int} primitive
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerPrimitiveField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("intPF");
    assertNotNull(f);


    assertTrue(e.supportsType(Integer.TYPE));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "intpf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "intPF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, 123, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("123"));


    // Test the decodeField method with a single value.
    assertEquals(o.getIntPF(), 0);

    e.decodeField(f, o, a);

    assertEquals(o.getIntPF(), 123);
  }



  /**
   * Provides test coverage for processing related to {@code int} primitive
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerPrimitiveArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("intPAF");
    assertNotNull(f);


    int[] ints = new int[2];
    ints[0] = 123;
    ints[1] = 456;
    assertTrue(e.supportsType(ints.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "intpaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "intPAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, ints, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("123"));
    assertTrue(a.hasValue("456"));


    // Test the decodeField method with multiple values.
    assertNull(o.getIntPAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getIntPAF());
    assertEquals(o.getIntPAF().length, 2);
    assertEquals(o.getIntPAF()[0], 123);
    assertEquals(o.getIntPAF()[1], 456);
  }



  /**
   * Provides test coverage for processing related to {@code int} primitive
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerPrimitiveGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getIntPM");
    assertNotNull(m);

    assertTrue(e.supportsType(Integer.TYPE));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "intpm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "intPM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, 123, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("123"));
  }



  /**
   * Provides test coverage for processing related to {@code int} primitive
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerPrimitiveArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getIntPAM");
    assertNotNull(m);

    int[] ints = new int[2];
    ints[0] = 123;
    ints[1] = 456;
    assertTrue(e.supportsType(ints.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "intpam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "intPAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, ints, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("123"));
    assertTrue(a.hasValue("456"));
  }



  /**
   * Provides test coverage for processing related to {@code int} primitive
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerPrimitiveSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setIntPM", Integer.TYPE);
    assertNotNull(m);

    assertTrue(e.supportsType(Integer.TYPE));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertEquals(o.getIntPM(), 0);

    e.invokeSetter(m, o, new Attribute("foo", "123"));

    assertEquals(o.getIntPM(), 123);
  }



  /**
   * Provides test coverage for processing related to {@code int} primitive
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerPrimitiveArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    int[] ints = new int[2];
    ints[0] = 123;
    ints[1] = 456;
    assertTrue(e.supportsType(ints.getClass()));

    Method m = o.getClass().getDeclaredMethod("setIntPAM", ints.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getIntPAM());

    e.invokeSetter(m, o, new Attribute("foo", "123", "456"));

    assertNotNull(o.getIntPAM());
    assertEquals(o.getIntPAM().length, 2);
    assertEquals(o.getIntPAM()[0], 123);
    assertEquals(o.getIntPAM()[1], 456);
  }



  /**
   * Provides test coverage for processing related to {@code Integer} object
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerObjectField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("intOF");
    assertNotNull(f);


    assertTrue(e.supportsType(Integer.class));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "intof-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "intOF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, Integer.valueOf(123), "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("123"));


    // Test the decodeField method with a single value.
    assertNull(o.getIntOF());

    e.decodeField(f, o, a);

    assertNotNull(o.getIntOF());
    assertEquals(o.getIntOF(), Integer.valueOf(123));
  }



  /**
   * Provides test coverage for processing related to {@code Integer} object
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerObjectArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("intOAF");
    assertNotNull(f);


    Integer[] ints = new Integer[2];
    ints[0] = Integer.valueOf(123);
    ints[1] = Integer.valueOf(456);
    assertTrue(e.supportsType(ints.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "intoaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "intOAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, ints, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("123"));
    assertTrue(a.hasValue("456"));


    // Test the decodeField method with multiple values.
    assertNull(o.getIntOAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getIntOAF());
    assertEquals(o.getIntOAF().length, 2);
    assertEquals(o.getIntOAF()[0], Integer.valueOf(123));
    assertEquals(o.getIntOAF()[1], Integer.valueOf(456));
  }



  /**
   * Provides test coverage for processing related to {@code Integer} object
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerObjectGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getIntOM");
    assertNotNull(m);

    assertTrue(e.supportsType(Integer.class));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "intom-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "intOM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, Integer.valueOf(123), "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("123"));
  }



  /**
   * Provides test coverage for processing related to {@code Integer} object
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerObjectArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getIntOAM");
    assertNotNull(m);

    Integer[] ints = new Integer[2];
    ints[0] = Integer.valueOf(123);
    ints[1] = Integer.valueOf(456);
    assertTrue(e.supportsType(ints.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "intoam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "intOAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, ints, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("123"));
    assertTrue(a.hasValue("456"));
  }



  /**
   * Provides test coverage for processing related to {@code Integer} object
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerObjectSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setIntOM", Integer.class);
    assertNotNull(m);

    assertTrue(e.supportsType(Integer.class));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getIntOM());

    e.invokeSetter(m, o, new Attribute("foo", "123"));

    assertNotNull(o.getIntOM());
    assertEquals(o.getIntOM(), Integer.valueOf(123));
  }



  /**
   * Provides test coverage for processing related to {@code Integer} object
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerObjectArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Integer[] ints = new Integer[2];
    ints[0] = Integer.valueOf(123);
    ints[1] = Integer.valueOf(456);
    assertTrue(e.supportsType(ints.getClass()));

    Method m = o.getClass().getDeclaredMethod("setIntOAM", ints.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getIntOAM());

    e.invokeSetter(m, o, new Attribute("foo", "123", "456"));

    assertNotNull(o.getIntOAM());
    assertEquals(o.getIntOAM().length, 2);
    assertEquals(o.getIntOAM()[0], Integer.valueOf(123));
    assertEquals(o.getIntOAM()[1], Integer.valueOf(456));
  }



  /**
   * Provides test coverage for processing related to {@code LDAPURL} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPURLField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("ldapURLF");
    assertNotNull(f);


    LDAPURL url = new LDAPURL("ldap://server.example.com/dc=example,dc=com");
    assertTrue(e.supportsType(url.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "ldapurlf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "ldapURLF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, url, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("ldap://server.example.com/dc=example,dc=com"));


    // Test the decodeField method with a single value.
    assertNull(o.getLDAPURLF());

    e.decodeField(f, o, a);

    assertNotNull(o.getLDAPURLF());
    assertEquals(o.getLDAPURLF(), url);
  }



  /**
   * Provides test coverage for processing related to {@code LDAPURL} array
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPURLArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("ldapURLAF");
    assertNotNull(f);


    LDAPURL[] urls = new LDAPURL[2];
    urls[0] = new LDAPURL("ldap://server1.example.com/dc=example,dc=com");
    urls[1] = new LDAPURL("ldap://server2.example.com/dc=example,dc=com");
    assertTrue(e.supportsType(urls.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "ldapurlaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "ldapURLAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, urls, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("ldap://server1.example.com/dc=example,dc=com"));
    assertTrue(a.hasValue("ldap://server2.example.com/dc=example,dc=com"));


    // Test the decodeField method with multiple values.
    assertNull(o.getLDAPURLAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getLDAPURLAF());
    assertEquals(o.getLDAPURLAF().length, 2);
    assertEquals(o.getLDAPURLAF()[0], urls[0]);
    assertEquals(o.getLDAPURLAF()[1], urls[1]);
  }



  /**
   * Provides test coverage for processing related to {@code LDAPURL} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPURLGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getLDAPURLM");
    assertNotNull(m);

    LDAPURL url = new LDAPURL("ldap://server.example.com/dc=example,dc=com");
    assertTrue(e.supportsType(url.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "ldapurlm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "ldapURLM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, url, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("ldap://server.example.com/dc=example,dc=com"));
  }



  /**
   * Provides test coverage for processing related to {@code LDAPURL} array
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPURLArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getLDAPURLAM");
    assertNotNull(m);

    LDAPURL[] urls = new LDAPURL[2];
    urls[0] = new LDAPURL("ldap://server1.example.com/dc=example,dc=com");
    urls[1] = new LDAPURL("ldap://server2.example.com/dc=example,dc=com");
    assertTrue(e.supportsType(urls.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "ldapurlam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "ldapURLAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, urls, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("ldap://server1.example.com/dc=example,dc=com"));
    assertTrue(a.hasValue("ldap://server2.example.com/dc=example,dc=com"));
  }



  /**
   * Provides test coverage for processing related to {@code LDAPURL} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPURLSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setLDAPURLM", LDAPURL.class);
    assertNotNull(m);

    LDAPURL url = new LDAPURL("ldap://server.example.com/dc=example,dc=com");
    assertTrue(e.supportsType(url.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getLDAPURLM());

    e.invokeSetter(m, o, new Attribute("foo",
         "ldap://server.example.com/dc=example,dc=com"));

    assertNotNull(o.getLDAPURLM());
    assertEquals(o.getLDAPURLM(), url);
  }



  /**
   * Provides test coverage for processing related to {@code LDAPURL} array
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPURLArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    LDAPURL[] urls = new LDAPURL[2];
    urls[0] = new LDAPURL("ldap://server1.example.com/dc=example,dc=com");
    urls[1] = new LDAPURL("ldap://server2.example.com/dc=example,dc=com");
    assertTrue(e.supportsType(urls.getClass()));

    Method m = o.getClass().getDeclaredMethod("setLDAPURLAM", urls.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getLDAPURLAM());

    e.invokeSetter(m, o, new Attribute("foo",
         "ldap://server1.example.com/dc=example,dc=com",
         "ldap://server2.example.com/dc=example,dc=com"));

    assertNotNull(o.getLDAPURLAM());
    assertEquals(o.getLDAPURLAM().length, 2);
    assertEquals(o.getLDAPURLAM()[0], urls[0]);
    assertEquals(o.getLDAPURLAM()[1], urls[1]);
  }



  /**
   * Provides test coverage for processing related to {@code long} primitive
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongPrimitiveField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("longPF");
    assertNotNull(f);


    assertTrue(e.supportsType(Long.TYPE));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "longpf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "longPF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, 123L, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("123"));


    // Test the decodeField method with a single value.
    assertEquals(o.getLongPF(), 0L);

    e.decodeField(f, o, a);

    assertEquals(o.getLongPF(), 123L);
  }



  /**
   * Provides test coverage for processing related to {@code long} primitive
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongPrimitiveArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("longPAF");
    assertNotNull(f);


    long[] longs = new long[2];
    longs[0] = 123L;
    longs[1] = 456L;
    assertTrue(e.supportsType(longs.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "longpaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "longPAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, longs, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("123"));
    assertTrue(a.hasValue("456"));


    // Test the decodeField method with multiple values.
    assertNull(o.getLongPAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getLongPAF());
    assertEquals(o.getLongPAF().length, 2);
    assertEquals(o.getLongPAF()[0], 123L);
    assertEquals(o.getLongPAF()[1], 456L);
  }



  /**
   * Provides test coverage for processing related to {@code long} primitive
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongPrimitiveGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getLongPM");
    assertNotNull(m);

    assertTrue(e.supportsType(Long.TYPE));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "longpm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "longPM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, 123L, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("123"));
  }



  /**
   * Provides test coverage for processing related to {@code long} primitive
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongPrimitiveArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getLongPAM");
    assertNotNull(m);

    long[] longs = new long[2];
    longs[0] = 123L;
    longs[1] = 456L;
    assertTrue(e.supportsType(longs.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "longpam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "longPAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, longs, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("123"));
    assertTrue(a.hasValue("456"));
  }



  /**
   * Provides test coverage for processing related to {@code long} primitive
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongPrimitiveSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setLongPM", Long.TYPE);
    assertNotNull(m);

    assertTrue(e.supportsType(Long.TYPE));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertEquals(o.getLongPM(), 0L);

    e.invokeSetter(m, o, new Attribute("foo", "123"));

    assertEquals(o.getLongPM(), 123L);
  }



  /**
   * Provides test coverage for processing related to {@code long} primitive
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongPrimitiveArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    long[] longs = new long[2];
    longs[0] = 123L;
    longs[1] = 456L;
    assertTrue(e.supportsType(longs.getClass()));

    Method m = o.getClass().getDeclaredMethod("setLongPAM", longs.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getLongPAM());

    e.invokeSetter(m, o, new Attribute("foo", "123", "456"));

    assertNotNull(o.getLongPAM());
    assertEquals(o.getLongPAM().length, 2);
    assertEquals(o.getLongPAM()[0], 123L);
    assertEquals(o.getLongPAM()[1], 456L);
  }



  /**
   * Provides test coverage for processing related to {@code Long} object
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongObjectField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("longOF");
    assertNotNull(f);


    assertTrue(e.supportsType(Long.class));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "longof-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "longOF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, Long.valueOf(123L), "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("123"));


    // Test the decodeField method with a single value.
    assertNull(o.getLongOF());

    e.decodeField(f, o, a);

    assertNotNull(o.getLongOF());
    assertEquals(o.getLongOF(), Long.valueOf(123L));
  }



  /**
   * Provides test coverage for processing related to {@code Long} object
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongObjectArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("longOAF");
    assertNotNull(f);


    Long[] longs = new Long[2];
    longs[0] = Long.valueOf(123L);
    longs[1] = Long.valueOf(456L);
    assertTrue(e.supportsType(longs.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "longoaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "longOAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, longs, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("123"));
    assertTrue(a.hasValue("456"));


    // Test the decodeField method with multiple values.
    assertNull(o.getLongOAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getLongOAF());
    assertEquals(o.getLongOAF().length, 2);
    assertEquals(o.getLongOAF()[0], Long.valueOf(123L));
    assertEquals(o.getLongOAF()[1], Long.valueOf(456L));
  }



  /**
   * Provides test coverage for processing related to {@code Long} object
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongObjectGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getLongOM");
    assertNotNull(m);

    assertTrue(e.supportsType(Long.class));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "longom-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "longOM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, Long.valueOf(123L), "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("123"));
  }



  /**
   * Provides test coverage for processing related to {@code Long} object
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongObjectArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getLongOAM");
    assertNotNull(m);

    Long[] longs = new Long[2];
    longs[0] = Long.valueOf(123L);
    longs[1] = Long.valueOf(456L);
    assertTrue(e.supportsType(longs.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "longoam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "longOAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, longs, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("123"));
    assertTrue(a.hasValue("456"));
  }



  /**
   * Provides test coverage for processing related to {@code Long} object
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongObjectSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setLongOM", Long.class);
    assertNotNull(m);

    assertTrue(e.supportsType(Long.class));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getLongOM());

    e.invokeSetter(m, o, new Attribute("foo", "123"));

    assertNotNull(o.getLongOM());
    assertEquals(o.getLongOM(), Long.valueOf(123L));
  }



  /**
   * Provides test coverage for processing related to {@code Long} object
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongObjectArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Long[] longs = new Long[2];
    longs[0] = Long.valueOf(123L);
    longs[1] = Long.valueOf(456L);
    assertTrue(e.supportsType(longs.getClass()));

    Method m = o.getClass().getDeclaredMethod("setLongOAM", longs.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getLongOAM());

    e.invokeSetter(m, o, new Attribute("foo", "123", "456"));

    assertNotNull(o.getLongOAM());
    assertEquals(o.getLongOAM().length, 2);
    assertEquals(o.getLongOAM()[0], Long.valueOf(123L));
    assertEquals(o.getLongOAM()[1], Long.valueOf(456L));
  }



  /**
   * Provides test coverage for processing related to {@code RDN} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRDNField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("rdnF");
    assertNotNull(f);


    RDN rdn = new RDN("dc=example");
    assertTrue(e.supportsType(rdn.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "rdnf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "rdnF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.12");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, rdn, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("dc=example"));


    // Test the decodeField method with a single value.
    assertNull(o.getRDNF());

    e.decodeField(f, o, a);

    assertNotNull(o.getRDNF());
    assertEquals(o.getRDNF(), new RDN("dc=example"));
  }



  /**
   * Provides test coverage for processing related to {@code RDN} array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRDNArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("rdnAF");
    assertNotNull(f);


    RDN[] rdns = new RDN[2];
    rdns[0] = new RDN("dc=example");
    rdns[1] = new RDN("o=example.com");
    assertTrue(e.supportsType(rdns.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "rdnaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "rdnAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.12");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, rdns, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("dc=example"));
    assertTrue(a.hasValue("o=example.com"));


    // Test the decodeField method with multiple values.
    assertNull(o.getRDNAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getRDNAF());
    assertEquals(o.getRDNAF().length, 2);
    assertEquals(o.getRDNAF()[0], new RDN("dc=example"));
    assertEquals(o.getRDNAF()[1], new RDN("o=example.com"));
  }



  /**
   * Provides test coverage for processing related to {@code RDN} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRDNGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getRDNM");
    assertNotNull(m);

    RDN rdn = new RDN("dc=example");
    assertTrue(e.supportsType(rdn.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "rdnm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "rdnM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.12");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, rdn, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("dc=example"));
  }



  /**
   * Provides test coverage for processing related to {@code RDN} array getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRDNArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getRDNAM");
    assertNotNull(m);

    RDN[] rdns = new RDN[2];
    rdns[0] = new RDN("dc=example");
    rdns[1] = new RDN("o=example.com");
    assertTrue(e.supportsType(rdns.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "rdnam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "rdnAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.12");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, rdns, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("dc=example"));
    assertTrue(a.hasValue("o=example.com"));
  }



  /**
   * Provides test coverage for processing related to {@code RDN} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRDNSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setRDNM", RDN.class);
    assertNotNull(m);

    RDN rdn = new RDN("dc=example");
    assertTrue(e.supportsType(rdn.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getRDNM());

    e.invokeSetter(m, o, new Attribute("foo", "dc=example"));

    assertNotNull(o.getRDNM());
    assertEquals(o.getRDNM(), new RDN("dc=example"));
  }



  /**
   * Provides test coverage for processing related to {@code RDN} array setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRDNArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    RDN[] rdns = new RDN[2];
    rdns[0] = new RDN("dc=example");
    rdns[1] = new RDN("o=example.com");
    assertTrue(e.supportsType(rdns.getClass()));

    Method m = o.getClass().getDeclaredMethod("setRDNAM", rdns.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getRDNAM());

    e.invokeSetter(m, o, new Attribute("foo", "dc=example", "o=example.com"));

    assertNotNull(o.getRDNAM());
    assertEquals(o.getRDNAM().length, 2);
    assertEquals(o.getRDNAM()[0], new RDN("dc=example"));
    assertEquals(o.getRDNAM()[1], new RDN("o=example.com"));
  }



  /**
   * Provides test coverage for processing related to {@code short} primitive
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShortPrimitiveField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("shortPF");
    assertNotNull(f);


    assertTrue(e.supportsType(Short.TYPE));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "shortpf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "shortPF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, (short) 123, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("123"));


    // Test the decodeField method with a single value.
    assertEquals(o.getShortPF(), 0);

    e.decodeField(f, o, a);

    assertEquals(o.getShortPF(), (short) 123);
  }



  /**
   * Provides test coverage for processing related to {@code short} primitive
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShortPrimitiveArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("shortPAF");
    assertNotNull(f);


    short[] shorts = new short[2];
    shorts[0] = 123;
    shorts[1] = 456;
    assertTrue(e.supportsType(shorts.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "shortpaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "shortPAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, shorts, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("123"));
    assertTrue(a.hasValue("456"));


    // Test the decodeField method with multiple values.
    assertNull(o.getShortPAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getShortPAF());
    assertEquals(o.getShortPAF().length, 2);
    assertEquals(o.getShortPAF()[0], (short) 123);
    assertEquals(o.getShortPAF()[1], (short) 456);
  }



  /**
   * Provides test coverage for processing related to {@code short} primitive
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShortPrimitiveGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getShortPM");
    assertNotNull(m);

    assertTrue(e.supportsType(Short.TYPE));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "shortpm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "shortPM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, (short) 123, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("123"));
  }



  /**
   * Provides test coverage for processing related to {@code short} primitive
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShortPrimitiveArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getShortPAM");
    assertNotNull(m);

    short[] shorts = new short[2];
    shorts[0] = 123;
    shorts[1] = 456;
    assertTrue(e.supportsType(shorts.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "shortpam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "shortPAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, shorts, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("123"));
    assertTrue(a.hasValue("456"));
  }



  /**
   * Provides test coverage for processing related to {@code short} primitive
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShortPrimitiveSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setShortPM", Short.TYPE);
    assertNotNull(m);

    assertTrue(e.supportsType(Short.TYPE));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertEquals(o.getShortPM(), (short) 0);

    e.invokeSetter(m, o, new Attribute("foo", "123"));

    assertEquals(o.getShortPM(), (short) 123);
  }



  /**
   * Provides test coverage for processing related to {@code short} primitive
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShortPrimitiveArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    short[] shorts = new short[2];
    shorts[0] = 123;
    shorts[1] = 456;
    assertTrue(e.supportsType(shorts.getClass()));

    Method m = o.getClass().getDeclaredMethod("setShortPAM", shorts.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getShortPAM());

    e.invokeSetter(m, o, new Attribute("foo", "123", "456"));

    assertNotNull(o.getShortPAM());
    assertEquals(o.getShortPAM().length, 2);
    assertEquals(o.getShortPAM()[0], (short) 123);
    assertEquals(o.getShortPAM()[1], (short) 456);
  }



  /**
   * Provides test coverage for processing related to {@code Short} object
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShortObjectField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("shortOF");
    assertNotNull(f);


    assertTrue(e.supportsType(Short.class));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "shortof-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "shortOF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, Short.valueOf((short) 123), "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("123"));


    // Test the decodeField method with a single value.
    assertNull(o.getShortOF());

    e.decodeField(f, o, a);

    assertNotNull(o.getShortOF());
    assertEquals(o.getShortOF(), Short.valueOf((short) 123));
  }



  /**
   * Provides test coverage for processing related to {@code Short} object
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShortObjectArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("shortOAF");
    assertNotNull(f);


    Short[] shorts = new Short[2];
    shorts[0] = Short.valueOf((short) 123);
    shorts[1] = Short.valueOf((short) 456);
    assertTrue(e.supportsType(shorts.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "shortoaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "shortOAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, shorts, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("123"));
    assertTrue(a.hasValue("456"));


    // Test the decodeField method with multiple values.
    assertNull(o.getShortOAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getShortOAF());
    assertEquals(o.getShortOAF().length, 2);
    assertEquals(o.getShortOAF()[0], Short.valueOf((short) 123));
    assertEquals(o.getShortOAF()[1], Short.valueOf((short) 456));
  }



  /**
   * Provides test coverage for processing related to {@code Short} object
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShortObjectGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getShortOM");
    assertNotNull(m);

    assertTrue(e.supportsType(Short.class));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "shortom-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "shortOM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, Short.valueOf((short) 123), "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("123"));
  }



  /**
   * Provides test coverage for processing related to {@code Short} object
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShortObjectArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getShortOAM");
    assertNotNull(m);

    Short[] shorts = new Short[2];
    shorts[0] = Short.valueOf((short) 123);
    shorts[1] = Short.valueOf((short) 456);
    assertTrue(e.supportsType(shorts.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "shortoam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "shortOAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.27");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, shorts, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("123"));
    assertTrue(a.hasValue("456"));
  }



  /**
   * Provides test coverage for processing related to {@code Short} object
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShortObjectSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setShortOM", Short.class);
    assertNotNull(m);

    assertTrue(e.supportsType(Short.class));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getShortOM());

    e.invokeSetter(m, o, new Attribute("foo", "123"));

    assertNotNull(o.getShortOM());
    assertEquals(o.getShortOM(), Short.valueOf((short) 123));
  }



  /**
   * Provides test coverage for processing related to {@code Short} object
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShortObjectArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Short[] shorts = new Short[2];
    shorts[0] = Short.valueOf((short) 123);
    shorts[1] = Short.valueOf((short) 456);
    assertTrue(e.supportsType(shorts.getClass()));

    Method m = o.getClass().getDeclaredMethod("setShortOAM", shorts.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getShortOAM());

    e.invokeSetter(m, o, new Attribute("foo", "123", "456"));

    assertNotNull(o.getShortOAM());
    assertEquals(o.getShortOAM().length, 2);
    assertEquals(o.getShortOAM()[0], Short.valueOf((short) 123));
    assertEquals(o.getShortOAM()[1], Short.valueOf((short) 456));
  }



  /**
   * Provides test coverage for processing related to {@code String} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringF");
    assertNotNull(f);


    String s = "bar";
    assertTrue(e.supportsType(s.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("bar"));


    // Test the decodeField method with a single value.
    assertNull(o.getStringF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringF());
    assertEquals(o.getStringF(), "bar");
  }



  /**
   * Provides test coverage for processing related to {@code String} array
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringAF");
    assertNotNull(f);


    String[] s = new String[2];
    s[0] = "bar";
    s[1] = "baz";
    assertTrue(e.supportsType(s.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("bar"));
    assertTrue(a.hasValue("baz"));


    // Test the decodeField method with multiple values.
    assertNull(o.getStringAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringAF());
    assertEquals(o.getStringAF().length, 2);
    assertEquals(o.getStringAF()[0], "bar");
    assertEquals(o.getStringAF()[1], "baz");
  }



  /**
   * Provides test coverage for processing related to {@code String} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringM");
    assertNotNull(m);

    String s = "bar";
    assertTrue(e.supportsType(s.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("bar"));
  }



  /**
   * Provides test coverage for processing related to {@code String} array
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringAM");
    assertNotNull(m);

    String[] s = new String[2];
    s[0] = "bar";
    s[1] = "baz";
    assertTrue(e.supportsType(s.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("bar"));
    assertTrue(a.hasValue("baz"));
  }



  /**
   * Provides test coverage for processing related to {@code String} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setStringM", String.class);
    assertNotNull(m);

    String s = "bar";
    assertTrue(e.supportsType(s.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringM());

    e.invokeSetter(m, o, new Attribute("foo", "bar"));

    assertNotNull(o.getStringM());
    assertEquals(o.getStringM(), "bar");
  }



  /**
   * Provides test coverage for processing related to {@code String} array
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    String[] s = new String[2];
    s[0] = "bar";
    s[1] = "baz";
    assertTrue(e.supportsType(s.getClass()));

    Method m = o.getClass().getDeclaredMethod("setStringAM", s.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringAM());

    e.invokeSetter(m, o, new Attribute("foo", "bar", "baz"));

    assertNotNull(o.getStringAM());
    assertEquals(o.getStringAM().length, 2);
    assertEquals(o.getStringAM()[0], "bar");
    assertEquals(o.getStringAM()[1], "baz");
  }



  /**
   * Provides test coverage for processing related to {@code StringBuffer}
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringBufferField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringBufferF");
    assertNotNull(f);


    StringBuffer s = new StringBuffer("bar");
    assertTrue(e.supportsType(s.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringbufferf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringBufferF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("bar"));


    // Test the decodeField method with a single value.
    assertNull(o.getStringBufferF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringBufferF());
    assertEquals(o.getStringBufferF().toString(), "bar");
  }



  /**
   * Provides test coverage for processing related to {@code StringBuffer} array
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringBufferArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringBufferAF");
    assertNotNull(f);


    StringBuffer[] s = new StringBuffer[2];
    s[0] = new StringBuffer("bar");
    s[1] = new StringBuffer("baz");
    assertTrue(e.supportsType(s.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringbufferaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringBufferAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("bar"));
    assertTrue(a.hasValue("baz"));


    // Test the decodeField method with multiple values.
    assertNull(o.getStringBufferAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringBufferAF());
    assertEquals(o.getStringBufferAF().length, 2);
    assertEquals(o.getStringBufferAF()[0].toString(), "bar");
    assertEquals(o.getStringBufferAF()[1].toString(), "baz");
  }



  /**
   * Provides test coverage for processing related to {@code StringBuffer}
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringBufferGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringBufferM");
    assertNotNull(m);

    StringBuffer s = new StringBuffer("bar");
    assertTrue(e.supportsType(s.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringbufferm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringBufferM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("bar"));
  }



  /**
   * Provides test coverage for processing related to {@code StringBuffer} array
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringBufferArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringBufferAM");
    assertNotNull(m);

    StringBuffer[] s = new StringBuffer[2];
    s[0] = new StringBuffer("bar");
    s[1] = new StringBuffer("baz");
    assertTrue(e.supportsType(s.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringbufferam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringBufferAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("bar"));
    assertTrue(a.hasValue("baz"));
  }



  /**
   * Provides test coverage for processing related to {@code StringBuffer}
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringBufferSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setStringBufferM",
         StringBuffer.class);
    assertNotNull(m);

    StringBuffer s = new StringBuffer("bar");
    assertTrue(e.supportsType(s.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringBufferM());

    e.invokeSetter(m, o, new Attribute("foo", "bar"));

    assertNotNull(o.getStringBufferM());
    assertEquals(o.getStringBufferM().toString(), "bar");
  }



  /**
   * Provides test coverage for processing related to {@code StringBuffer} array
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringBufferArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    StringBuffer[] s = new StringBuffer[2];
    s[0] = new StringBuffer("bar");
    s[1] = new StringBuffer("baz");
    assertTrue(e.supportsType(s.getClass()));

    Method m = o.getClass().getDeclaredMethod("setStringBufferAM",
         s.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringBufferAM());

    e.invokeSetter(m, o, new Attribute("foo", "bar", "baz"));

    assertNotNull(o.getStringBufferAM());
    assertEquals(o.getStringBufferAM().length, 2);
    assertEquals(o.getStringBufferAM()[0].toString(), "bar");
    assertEquals(o.getStringBufferAM()[1].toString(), "baz");
  }



  /**
   * Provides test coverage for processing related to {@code StringBuilder}
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringBuilderField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringBuilderF");
    assertNotNull(f);


    StringBuilder s = new StringBuilder("bar");
    assertTrue(e.supportsType(s.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringbuilderf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringBuilderF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("bar"));


    // Test the decodeField method with a single value.
    assertNull(o.getStringBuilderF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringBuilderF());
    assertEquals(o.getStringBuilderF().toString(), "bar");
  }



  /**
   * Provides test coverage for processing related to {@code StringBuilder}
   * array fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringBuilderArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringBuilderAF");
    assertNotNull(f);


    StringBuilder[] s = new StringBuilder[2];
    s[0] = new StringBuilder("bar");
    s[1] = new StringBuilder("baz");
    assertTrue(e.supportsType(s.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringbuilderaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringBuilderAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("bar"));
    assertTrue(a.hasValue("baz"));


    // Test the decodeField method with multiple values.
    assertNull(o.getStringBuilderAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringBuilderAF());
    assertEquals(o.getStringBuilderAF().length, 2);
    assertEquals(o.getStringBuilderAF()[0].toString(), "bar");
    assertEquals(o.getStringBuilderAF()[1].toString(), "baz");
  }



  /**
   * Provides test coverage for processing related to {@code StringBuilder}
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringBuilderGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringBuilderM");
    assertNotNull(m);

    StringBuilder s = new StringBuilder("bar");
    assertTrue(e.supportsType(s.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringbuilderm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringBuilderM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue("bar"));
  }



  /**
   * Provides test coverage for processing related to {@code StringBuilder}
   * array getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringBuilderArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringBuilderAM");
    assertNotNull(m);

    StringBuilder[] s = new StringBuilder[2];
    s[0] = new StringBuilder("bar");
    s[1] = new StringBuilder("baz");
    assertTrue(e.supportsType(s.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringbuilderam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringBuilderAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue("bar"));
    assertTrue(a.hasValue("baz"));
  }



  /**
   * Provides test coverage for processing related to {@code StringBuilder}
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringBuilderSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setStringBuilderM",
         StringBuilder.class);
    assertNotNull(m);

    StringBuilder s = new StringBuilder("bar");
    assertTrue(e.supportsType(s.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringBuilderM());

    e.invokeSetter(m, o, new Attribute("foo", "bar"));

    assertNotNull(o.getStringBuilderM());
    assertEquals(o.getStringBuilderM().toString(), "bar");
  }



  /**
   * Provides test coverage for processing related to {@code StringBuilder}
   * array setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringBuilderArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    StringBuilder[] s = new StringBuilder[2];
    s[0] = new StringBuilder("bar");
    s[1] = new StringBuilder("baz");
    assertTrue(e.supportsType(s.getClass()));

    Method m = o.getClass().getDeclaredMethod("setStringBuilderAM",
         s.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringBuilderAM());

    e.invokeSetter(m, o, new Attribute("foo", "bar", "baz"));

    assertNotNull(o.getStringBuilderAM());
    assertEquals(o.getStringBuilderAM().length, 2);
    assertEquals(o.getStringBuilderAM()[0].toString(), "bar");
    assertEquals(o.getStringBuilderAM()[1].toString(), "baz");
  }



  /**
   * Provides test coverage for processing related to {@code URI} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testURIField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("uriF");
    assertNotNull(f);


    URI uri = new URI("http://localhost/test.txt");
    assertTrue(e.supportsType(uri.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "urif-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "uriF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, uri, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue(uri.toASCIIString()));


    // Test the decodeField method with a single value.
    assertNull(o.getURIF());

    e.decodeField(f, o, a);

    assertNotNull(o.getURIF());
    assertEquals(o.getURIF().toASCIIString(), uri.toASCIIString());
  }



  /**
   * Provides test coverage for processing related to {@code URI} array
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testURIArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("uriAF");
    assertNotNull(f);


    URI[] uris = new URI[2];
    uris[0] = new URI("http://localhost/file1.txt");
    uris[1] = new URI("http://localhost/file2.txt");
    assertTrue(e.supportsType(uris.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "uriaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "uriAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, uris, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue(uris[0].toASCIIString()));
    assertTrue(a.hasValue(uris[1].toASCIIString()));


    // Test the decodeField method with multiple values.
    assertNull(o.getURIAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getURIAF());
    assertEquals(o.getURIAF().length, 2);
    assertEquals(o.getURIAF()[0], uris[0]);
    assertEquals(o.getURIAF()[1], uris[1]);
  }



  /**
   * Provides test coverage for processing related to {@code URI} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testURIGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getURIM");
    assertNotNull(m);

    URI uri = new URI("http://localhost/test.txt");
    assertTrue(e.supportsType(uri.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "urim-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "uriM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, uri, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue(uri.toASCIIString()));
  }



  /**
   * Provides test coverage for processing related to {@code URI} array
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testURIArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getURIAM");
    assertNotNull(m);

    URI[] uris = new URI[2];
    uris[0] = new URI("http://localhost/file1.txt");
    uris[1] = new URI("http://localhost/file1.txt");
    assertTrue(e.supportsType(uris.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "uriam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "uriAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, uris, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue(uris[0].toASCIIString()));
    assertTrue(a.hasValue(uris[1].toASCIIString()));
  }



  /**
   * Provides test coverage for processing related to {@code URI} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testURISetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setURIM", URI.class);
    assertNotNull(m);

    URI uri = new URI("http://localhost/test.txt");
    assertTrue(e.supportsType(uri.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getURIM());

    e.invokeSetter(m, o, new Attribute("foo", uri.toASCIIString()));

    assertNotNull(o.getURIM());
    assertEquals(o.getURIM(), uri);
  }



  /**
   * Provides test coverage for processing related to {@code URI} array
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testURIArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    URI[] uris = new URI[2];
    uris[0] = new URI("http://localhost/file1.txt");
    uris[1] = new URI("http://localhost/file2.txt");
    assertTrue(e.supportsType(uris.getClass()));

    Method m = o.getClass().getDeclaredMethod("setURIAM", uris.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getURIAM());

    e.invokeSetter(m, o, new Attribute("foo", uris[0].toASCIIString(),
         uris[1].toASCIIString()));

    assertNotNull(o.getURIAM());
    assertEquals(o.getURIAM().length, 2);
    assertEquals(o.getURIAM()[0], uris[0]);
    assertEquals(o.getURIAM()[1], uris[1]);
  }



  /**
   * Provides test coverage for processing related to {@code URL} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testURLField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("urlF");
    assertNotNull(f);


    URL url = new URL("http://localhost/test.txt");
    assertTrue(e.supportsType(url.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "urlf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "urlF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, url, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue(url.toExternalForm()));


    // Test the decodeField method with a single value.
    assertNull(o.getURLF());

    e.decodeField(f, o, a);

    assertNotNull(o.getURLF());
    assertEquals(o.getURLF().toExternalForm(), url.toExternalForm());
  }



  /**
   * Provides test coverage for processing related to {@code URL} array
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testURLArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("urlAF");
    assertNotNull(f);


    URL[] urls = new URL[2];
    urls[0] = new URL("http://localhost/file1.txt");
    urls[1] = new URL("http://localhost/file2.txt");
    assertTrue(e.supportsType(urls.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "urlaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "urlAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, urls, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue(urls[0].toExternalForm()));
    assertTrue(a.hasValue(urls[1].toExternalForm()));


    // Test the decodeField method with multiple values.
    assertNull(o.getURLAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getURLAF());
    assertEquals(o.getURLAF().length, 2);
    assertEquals(o.getURLAF()[0], urls[0]);
    assertEquals(o.getURLAF()[1], urls[1]);
  }



  /**
   * Provides test coverage for processing related to {@code URL} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testURLGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getURLM");
    assertNotNull(m);

    URL url = new URL("http://localhost/test.txt");
    assertTrue(e.supportsType(url.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "urlm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "urlM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, url, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue(url.toExternalForm()));
  }



  /**
   * Provides test coverage for processing related to {@code URL} array
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testURLArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getURLAM");
    assertNotNull(m);

    URL[] urls = new URL[2];
    urls[0] = new URL("http://localhost/file1.txt");
    urls[1] = new URL("http://localhost/file1.txt");
    assertTrue(e.supportsType(urls.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "urlam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "urlAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, urls, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue(urls[0].toExternalForm()));
    assertTrue(a.hasValue(urls[1].toExternalForm()));
  }



  /**
   * Provides test coverage for processing related to {@code URL} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testURLSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setURLM", URL.class);
    assertNotNull(m);

    URL url = new URL("http://localhost/test.txt");
    assertTrue(e.supportsType(url.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getURLM());

    e.invokeSetter(m, o, new Attribute("foo", url.toExternalForm()));

    assertNotNull(o.getURLM());
    assertEquals(o.getURLM(), url);
  }



  /**
   * Provides test coverage for processing related to {@code URL} array
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testURLArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    URL[] urls = new URL[2];
    urls[0] = new URL("http://localhost/file1.txt");
    urls[1] = new URL("http://localhost/file2.txt");
    assertTrue(e.supportsType(urls.getClass()));

    Method m = o.getClass().getDeclaredMethod("setURLAM", urls.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getURLAM());

    e.invokeSetter(m, o, new Attribute("foo", urls[0].toExternalForm(),
         urls[1].toExternalForm()));

    assertNotNull(o.getURLAM());
    assertEquals(o.getURLAM().length, 2);
    assertEquals(o.getURLAM()[0], urls[0]);
    assertEquals(o.getURLAM()[1], urls[1]);
  }



  /**
   * Provides test coverage for processing related to {@code UUID} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUUIDField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("uuidF");
    assertNotNull(f);


    UUID uuid = UUID.randomUUID();
    assertTrue(e.supportsType(uuid.getClass()));
    assertFalse(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "uuidf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "uuidF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, uuid, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue(uuid.toString()));


    // Test the decodeField method with a single value.
    assertNull(o.getUUIDF());

    e.decodeField(f, o, a);

    assertNotNull(o.getUUIDF());
    assertEquals(o.getUUIDF().toString(), uuid.toString());
  }



  /**
   * Provides test coverage for processing related to {@code UUID} array
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUUIDArrayField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("uuidAF");
    assertNotNull(f);


    UUID[] uuids = new UUID[2];
    uuids[0] = UUID.randomUUID();
    uuids[1] = UUID.randomUUID();
    assertTrue(e.supportsType(uuids.getClass()));
    assertTrue(e.supportsMultipleValues(f));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "uuidaf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "uuidAF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, uuids, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue(uuids[0].toString()));
    assertTrue(a.hasValue(uuids[1].toString()));


    // Test the decodeField method with multiple values.
    assertNull(o.getUUIDAF());

    e.decodeField(f, o, a);

    assertNotNull(o.getUUIDAF());
    assertEquals(o.getUUIDAF().length, 2);
    assertEquals(o.getUUIDAF()[0], uuids[0]);
    assertEquals(o.getUUIDAF()[1], uuids[1]);
  }



  /**
   * Provides test coverage for processing related to {@code UUID} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUUIDGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getUUIDM");
    assertNotNull(m);

    UUID uuid = UUID.randomUUID();
    assertTrue(e.supportsType(uuid.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "uuidm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "uuidM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, uuid, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 1);
    assertTrue(a.hasValue(uuid.toString()));
  }



  /**
   * Provides test coverage for processing related to {@code UUID} array
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUUIDArrayGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getUUIDAM");
    assertNotNull(m);

    UUID[] uuids = new UUID[2];
    uuids[0] = UUID.randomUUID();
    uuids[1] = UUID.randomUUID();
    assertTrue(e.supportsType(uuids.getClass()));


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "uuidam-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "uuidAM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, uuids, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 2);
    assertTrue(a.hasValue(uuids[0].toString()));
    assertTrue(a.hasValue(uuids[1].toString()));
  }



  /**
   * Provides test coverage for processing related to {@code UUID} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUUIDSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setUUIDM", UUID.class);
    assertNotNull(m);

    UUID uuid = UUID.randomUUID();
    assertTrue(e.supportsType(uuid.getClass()));
    assertFalse(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getUUIDM());

    e.invokeSetter(m, o, new Attribute("foo", uuid.toString()));

    assertNotNull(o.getUUIDM());
    assertEquals(o.getUUIDM(), uuid);
  }



  /**
   * Provides test coverage for processing related to {@code UUID} array
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUUIDArraySetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    UUID[] uuids = new UUID[2];
    uuids[0] = UUID.randomUUID();
    uuids[1] = UUID.randomUUID();
    assertTrue(e.supportsType(uuids.getClass()));

    Method m = o.getClass().getDeclaredMethod("setUUIDAM", uuids.getClass());
    assertNotNull(m);
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getUUIDAM());

    e.invokeSetter(m, o, new Attribute("foo", uuids[0].toString(),
         uuids[1].toString()));

    assertNotNull(o.getUUIDAM());
    assertEquals(o.getUUIDAM().length, 2);
    assertEquals(o.getUUIDAM()[0], uuids[0]);
    assertEquals(o.getUUIDAM()[1], uuids[1]);
  }



  /**
   * Provides test coverage for processing related to {@code ArrayList} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testArrayListField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringArrayListF");
    assertNotNull(f);
    assertTrue(e.supportsType(f.getGenericType()));
    assertTrue(e.supportsMultipleValues(f));

    ArrayList<String> l = new ArrayList<String>(3);
    l.add("first");
    l.add("second");
    l.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringarraylistf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringArrayListF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, l, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));


    // Test the decodeField method with a single value.
    assertNull(o.getStringArrayListF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringArrayListF());
    assertEquals(o.getStringArrayListF(), l);
  }



  /**
   * Provides test coverage for processing related to {@code ArrayList} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testArrayListGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringArrayListM");
    assertNotNull(m);
    assertTrue(e.supportsType(m.getGenericReturnType()));

    ArrayList<String> l = new ArrayList<String>(3);
    l.add("first");
    l.add("second");
    l.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringarraylistm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringArrayListM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, l, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));
  }



  /**
   * Provides test coverage for processing related to {@code ArrayList} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testArrayListSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    ArrayList<String> l = new ArrayList<String>(3);
    l.add("first");
    l.add("second");
    l.add("third");

    Method m = o.getClass().getDeclaredMethod("setStringArrayListM",
         ArrayList.class);
    assertNotNull(m);

    assertTrue(e.supportsType(m.getGenericParameterTypes()[0]));
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringArrayListM());

    e.invokeSetter(m, o, new Attribute("foo", l));

    assertNotNull(o.getStringArrayListM());
    assertEquals(o.getStringArrayListM(), l);
  }



  /**
   * Provides test coverage for processing related to {@code LinkedList} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLinkedListField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringLinkedListF");
    assertNotNull(f);
    assertTrue(e.supportsType(f.getGenericType()));
    assertTrue(e.supportsMultipleValues(f));

    LinkedList<String> l = new LinkedList<String>();
    l.add("first");
    l.add("second");
    l.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringlinkedlistf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringLinkedListF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, l, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));


    // Test the decodeField method with a single value.
    assertNull(o.getStringLinkedListF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringLinkedListF());
    assertEquals(o.getStringLinkedListF(), l);
  }



  /**
   * Provides test coverage for processing related to {@code LinkedList} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLinkedListGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringLinkedListM");
    assertNotNull(m);
    assertTrue(e.supportsType(m.getGenericReturnType()));

    LinkedList<String> l = new LinkedList<String>();
    l.add("first");
    l.add("second");
    l.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringlinkedlistm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringLinkedListM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, l, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));
  }



  /**
   * Provides test coverage for processing related to {@code LinkedList} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLinkedListSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    LinkedList<String> l = new LinkedList<String>();
    l.add("first");
    l.add("second");
    l.add("third");

    Method m = o.getClass().getDeclaredMethod("setStringLinkedListM",
         LinkedList.class);
    assertNotNull(m);

    assertTrue(e.supportsType(m.getGenericParameterTypes()[0]));
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringLinkedListM());

    e.invokeSetter(m, o, new Attribute("foo", l));

    assertNotNull(o.getStringLinkedListM());
    assertEquals(o.getStringLinkedListM(), l);
  }



  /**
   * Provides test coverage for processing related to
   * {@code CopyOnWriteArrayList} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCopyOnWriteArrayListField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringCopyOnWriteArrayListF");
    assertNotNull(f);
    assertTrue(e.supportsType(f.getGenericType()));
    assertTrue(e.supportsMultipleValues(f));

    CopyOnWriteArrayList<String> l = new CopyOnWriteArrayList<String>();
    l.add("first");
    l.add("second");
    l.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringcopyonwritearraylistf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringCopyOnWriteArrayListF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, l, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));


    // Test the decodeField method with a single value.
    assertNull(o.getStringCopyOnWriteArrayListF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringCopyOnWriteArrayListF());
    assertEquals(o.getStringCopyOnWriteArrayListF(), l);
  }



  /**
   * Provides test coverage for processing related to
   * {@code CopyOnWriteArrayList} getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCopyOnWriteArrayListGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringCopyOnWriteArrayListM");
    assertNotNull(m);
    assertTrue(e.supportsType(m.getGenericReturnType()));

    CopyOnWriteArrayList<String> l = new CopyOnWriteArrayList<String>();
    l.add("first");
    l.add("second");
    l.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringcopyonwritearraylistm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringCopyOnWriteArrayListM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, l, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));
  }



  /**
   * Provides test coverage for processing related to
   * {@code CopyOnWriteArrayList} setter  methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCopyOnWriteArrayListSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    CopyOnWriteArrayList<String> l = new CopyOnWriteArrayList<String>();
    l.add("first");
    l.add("second");
    l.add("third");

    Method m = o.getClass().getDeclaredMethod("setStringCopyOnWriteArrayListM",
         CopyOnWriteArrayList.class);
    assertNotNull(m);

    assertTrue(e.supportsType(m.getGenericParameterTypes()[0]));
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringCopyOnWriteArrayListM());

    e.invokeSetter(m, o, new Attribute("foo", l));

    assertNotNull(o.getStringCopyOnWriteArrayListM());
    assertEquals(o.getStringCopyOnWriteArrayListM(), l);
  }



  /**
   * Provides test coverage for processing related to generic {@code List}
   * 3fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericListField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringListF");
    assertNotNull(f);
    assertTrue(e.supportsType(f.getGenericType()));
    assertTrue(e.supportsMultipleValues(f));

    List<String> l = new ArrayList<String>(3);
    l.add("first");
    l.add("second");
    l.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringlistf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringListF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, l, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));


    // Test the decodeField method with a single value.
    assertNull(o.getStringListF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringListF());
    assertEquals(o.getStringListF(), l);
  }



  /**
   * Provides test coverage for processing related to generic {@code List}
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericListGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringListM");
    assertNotNull(m);
    assertTrue(e.supportsType(m.getGenericReturnType()));

    List<String> l = new ArrayList<String>(3);
    l.add("first");
    l.add("second");
    l.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringlistm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringListM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, l, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));
  }



  /**
   * Provides test coverage for processing related to generic {@code List}
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericListSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    List<String> l = new ArrayList<String>(3);
    l.add("first");
    l.add("second");
    l.add("third");

    Method m = o.getClass().getDeclaredMethod("setStringListM", List.class);
    assertNotNull(m);

    assertTrue(e.supportsType(m.getGenericParameterTypes()[0]));
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringListM());

    e.invokeSetter(m, o, new Attribute("foo", l));

    assertNotNull(o.getStringListM());
    assertEquals(o.getStringListM(), l);
  }



  /**
   * Provides test coverage for processing related to {@code HashSet} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashSetField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringHashSetF");
    assertNotNull(f);
    assertTrue(e.supportsType(f.getGenericType()));
    assertTrue(e.supportsMultipleValues(f));

    HashSet<String> s = new HashSet<String>(3);
    s.add("first");
    s.add("second");
    s.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringhashsetf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringHashSetF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));


    // Test the decodeField method with a single value.
    assertNull(o.getStringHashSetF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringHashSetF());
    assertEquals(o.getStringHashSetF().size(), 3);
    assertTrue(o.getStringHashSetF().containsAll(s));
  }



  /**
   * Provides test coverage for processing related to {@code HashSet} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashSetGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringHashSetM");
    assertNotNull(m);
    assertTrue(e.supportsType(m.getGenericReturnType()));

    HashSet<String> s = new HashSet<String>(3);
    s.add("first");
    s.add("second");
    s.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringhashsetm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringHashSetM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));
  }



  /**
   * Provides test coverage for processing related to {@code HashSet} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashSetSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    HashSet<String> s = new HashSet<String>(3);
    s.add("first");
    s.add("second");
    s.add("third");

    Method m = o.getClass().getDeclaredMethod("setStringHashSetM",
         HashSet.class);
    assertNotNull(m);

    assertTrue(e.supportsType(m.getGenericParameterTypes()[0]));
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringHashSetM());

    e.invokeSetter(m, o, new Attribute("foo", s));

    assertNotNull(o.getStringHashSetM());
    assertEquals(o.getStringHashSetM().size(), 3);
    assertTrue(o.getStringHashSetM().containsAll(s));
  }



  /**
   * Provides test coverage for processing related to {@code LinkedHashSet}
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLinkedHashSetField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringLinkedHashSetF");
    assertNotNull(f);
    assertTrue(e.supportsType(f.getGenericType()));
    assertTrue(e.supportsMultipleValues(f));

    LinkedHashSet<String> s = new LinkedHashSet<String>(3);
    s.add("first");
    s.add("second");
    s.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringlinkedhashsetf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringLinkedHashSetF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));


    // Test the decodeField method with a single value.
    assertNull(o.getStringLinkedHashSetF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringLinkedHashSetF());
    assertEquals(o.getStringLinkedHashSetF().size(), 3);
    assertTrue(o.getStringLinkedHashSetF().containsAll(s));
  }



  /**
   * Provides test coverage for processing related to {@code LinkedHashSet}
   * getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLinkedHashSetGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringLinkedHashSetM");
    assertNotNull(m);
    assertTrue(e.supportsType(m.getGenericReturnType()));

    LinkedHashSet<String> s = new LinkedHashSet<String>(3);
    s.add("first");
    s.add("second");
    s.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringlinkedhashsetm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringLinkedHashSetM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));
  }



  /**
   * Provides test coverage for processing related to {@code LinkedHashSet}
   * setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLinkedHashSetSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    LinkedHashSet<String> s = new LinkedHashSet<String>(3);
    s.add("first");
    s.add("second");
    s.add("third");

    Method m = o.getClass().getDeclaredMethod("setStringLinkedHashSetM",
         LinkedHashSet.class);
    assertNotNull(m);

    assertTrue(e.supportsType(m.getGenericParameterTypes()[0]));
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringLinkedHashSetM());

    e.invokeSetter(m, o, new Attribute("foo", s));

    assertNotNull(o.getStringLinkedHashSetM());
    assertEquals(o.getStringLinkedHashSetM().size(), 3);
    assertTrue(o.getStringLinkedHashSetM().containsAll(s));
  }



  /**
   * Provides test coverage for processing related to {@code TreeSet} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTreeSetField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringTreeSetF");
    assertNotNull(f);
    assertTrue(e.supportsType(f.getGenericType()));
    assertTrue(e.supportsMultipleValues(f));

    TreeSet<String> s = new TreeSet<String>();
    s.add("first");
    s.add("second");
    s.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringtreesetf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringTreeSetF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));


    // Test the decodeField method with a single value.
    assertNull(o.getStringTreeSetF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringTreeSetF());
    assertEquals(o.getStringTreeSetF().size(), 3);
    assertTrue(o.getStringTreeSetF().containsAll(s));
  }



  /**
   * Provides test coverage for processing related to {@code TreeSet} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTreeSetGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringTreeSetM");
    assertNotNull(m);
    assertTrue(e.supportsType(m.getGenericReturnType()));

    TreeSet<String> s = new TreeSet<String>();
    s.add("first");
    s.add("second");
    s.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringtreesetm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringTreeSetM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));
  }



  /**
   * Provides test coverage for processing related to {@code TreeSet} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTreeSetSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    TreeSet<String> s = new TreeSet<String>();
    s.add("first");
    s.add("second");
    s.add("third");

    Method m = o.getClass().getDeclaredMethod("setStringTreeSetM",
         TreeSet.class);
    assertNotNull(m);

    assertTrue(e.supportsType(m.getGenericParameterTypes()[0]));
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringTreeSetM());

    e.invokeSetter(m, o, new Attribute("foo", s));

    assertNotNull(o.getStringTreeSetM());
    assertEquals(o.getStringTreeSetM().size(), 3);
    assertTrue(o.getStringTreeSetM().containsAll(s));
  }



  /**
   * Provides test coverage for processing related to
   * {@code CopyOnWriteArraySet} fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCopyOnWriteArraySetField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringCopyOnWriteArraySetF");
    assertNotNull(f);
    assertTrue(e.supportsType(f.getGenericType()));
    assertTrue(e.supportsMultipleValues(f));

    CopyOnWriteArraySet<String> s = new CopyOnWriteArraySet<String>();
    s.add("first");
    s.add("second");
    s.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringcopyonwritearraysetf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringCopyOnWriteArraySetF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));


    // Test the decodeField method with a single value.
    assertNull(o.getStringCopyOnWriteArraySetF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringCopyOnWriteArraySetF());
    assertEquals(o.getStringCopyOnWriteArraySetF().size(), 3);
    assertTrue(o.getStringCopyOnWriteArraySetF().containsAll(s));
  }



  /**
   * Provides test coverage for processing related to
   * {@code CopyOnWriteArraySet} getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCopyOnWriteArraySetGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringCopyOnWriteArraySetM");
    assertNotNull(m);
    assertTrue(e.supportsType(m.getGenericReturnType()));

    CopyOnWriteArraySet<String> s = new CopyOnWriteArraySet<String>();
    s.add("first");
    s.add("second");
    s.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringcopyonwritearraysetm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringCopyOnWriteArraySetM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));
  }



  /**
   * Provides test coverage for processing related to
   * {@code CopyOnWriteArraySet} setter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCopyOnWriteArraySetSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    CopyOnWriteArraySet<String> s = new CopyOnWriteArraySet<String>();
    s.add("first");
    s.add("second");
    s.add("third");

    Method m = o.getClass().getDeclaredMethod("setStringCopyOnWriteArraySetM",
         CopyOnWriteArraySet.class);
    assertNotNull(m);

    assertTrue(e.supportsType(m.getGenericParameterTypes()[0]));
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringCopyOnWriteArraySetM());

    e.invokeSetter(m, o, new Attribute("foo", s));

    assertNotNull(o.getStringCopyOnWriteArraySetM());
    assertEquals(o.getStringCopyOnWriteArraySetM().size(), 3);
    assertTrue(o.getStringCopyOnWriteArraySetM().containsAll(s));
  }



  /**
   * Provides test coverage for processing related to generic {@code Set}
   * fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericSetField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("stringSetF");
    assertNotNull(f);
    assertTrue(e.supportsType(f.getGenericType()));
    assertTrue(e.supportsMultipleValues(f));

    Set<String> s = new HashSet<String>(3);
    s.add("first");
    s.add("second");
    s.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringsetf-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringSetF");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeFieldValue method.
    Attribute a = e.encodeFieldValue(f, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));


    // Test the decodeField method with a single value.
    assertNull(o.getStringSetF());

    e.decodeField(f, o, a);

    assertNotNull(o.getStringSetF());
    assertEquals(o.getStringSetF().size(), 3);
    assertTrue(o.getStringSetF().containsAll(s));
  }



  /**
   * Provides test coverage for processing related to generic {@code Set} getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericSetGetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getStringSetM");
    assertNotNull(m);
    assertTrue(e.supportsType(m.getGenericReturnType()));

    Set<String> s = new HashSet<String>(3);
    s.add("first");
    s.add("second");
    s.add("third");


    // Test the constructAttributeType method.
    AttributeTypeDefinition d = e.constructAttributeType(m);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "stringsetm-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "stringSetM");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertFalse(d.isSingleValued());


    // Test the encodeMethodValue method.
    Attribute a = e.encodeMethodValue(m, s, "foo");
    assertNotNull(a);

    assertNotNull(a.getName());
    assertEquals(a.getName(), "foo");

    assertEquals(a.size(), 3);
    assertTrue(a.hasValue("first"));
    assertTrue(a.hasValue("second"));
    assertTrue(a.hasValue("third"));
  }



  /**
   * Provides test coverage for processing related to generic {@code Set} setter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericSetSetter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Set<String> s = new HashSet<String>(3);
    s.add("first");
    s.add("second");
    s.add("third");

    Method m = o.getClass().getDeclaredMethod("setStringSetM", Set.class);
    assertNotNull(m);

    assertTrue(e.supportsType(m.getGenericParameterTypes()[0]));
    assertTrue(e.supportsMultipleValues(m));


    // Test the invokeSetter method.
    assertNull(o.getStringSetM());

    e.invokeSetter(m, o, new Attribute("foo", s));

    assertNotNull(o.getStringSetM());
    assertEquals(o.getStringSetM().size(), 3);
    assertTrue(o.getStringSetM().containsAll(s));
  }



  /**
   * Provides test coverage for the {@code supportsType} method for types that
   * are not supported.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSupportsTypeUnsupported()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    assertFalse(e.supportsType(Byte.TYPE));

    assertFalse(e.supportsType(Character.TYPE));

    assertFalse(e.supportsType(Object.class));

    Object[] o = new Object[0];
    assertFalse(e.supportsType(o.getClass()));
  }



  /**
   * Provides test coverage for the {@code constructAttributeType} method for
   * a field that has an explicitly-named attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructAttributeTypeExplicitlyNamedField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("rdnField");
    assertNotNull(f);

    AttributeTypeDefinition d = e.constructAttributeType(f);
    assertNotNull(d);

    assertNotNull(d.getOID());
    assertEquals(d.getOID(), "cn-oid");

    assertNotNull(d.getNames());
    assertEquals(d.getNames().length, 1);

    assertNotNull(d.getNameOrOID());
    assertEquals(d.getNameOrOID(), "cn");

    assertNotNull(d.getSyntaxOID());
    assertEquals(d.getSyntaxOID(), "1.3.6.1.4.1.1466.115.121.1.15");

    assertTrue(d.isSingleValued());
  }



  /**
   * Provides test coverage for the {@code encodeFieldValue} method for a field
   * with an unsupported type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testEncodeFieldValueUnsupportedType()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultEncoderUnsupportedType o =
         new TestDefaultEncoderUnsupportedType();

    Field f = o.getClass().getDeclaredField("fieldValue");
    assertNotNull(f);

    e.encodeFieldValue(f, new Object(), "foo");
  }



  /**
   * Provides test coverage for the {@code encodeFieldValue} method for a field
   * with an unsupported array type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testEncodeFieldValueUnsupportedArrayType()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultEncoderUnsupportedType o =
         new TestDefaultEncoderUnsupportedType();

    Field f = o.getClass().getDeclaredField("fieldArrayValue");
    assertNotNull(f);

    e.encodeFieldValue(f, new Object[] { new Object() }, "foo");
  }



  /**
   * Provides test coverage for the {@code encodeMethodValue} method for a
   * method with an unsupported type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testEncodeMethodValueUnsupportedType()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultEncoderUnsupportedType o =
         new TestDefaultEncoderUnsupportedType();

    Method m = o.getClass().getDeclaredMethod("getMethodValue");
    assertNotNull(m);

    e.encodeMethodValue(m, new Object(), "foo");
  }



  /**
   * Provides test coverage for the {@code encodeMethodValue} method for a
   * method with an unsupported array type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testEncodeMethodValueUnsupportedArrayType()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultEncoderUnsupportedType o =
         new TestDefaultEncoderUnsupportedType();

    Method m = o.getClass().getDeclaredMethod("getMethodArrayValue");
    assertNotNull(m);

    e.encodeMethodValue(m, new Object[] { new Object() }, "foo");
  }



  /**
   * Provides test coverage for the {@code decodeField} method for a malformed
   * Boolean value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldMalformedBoolean()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("booleanPF");
    assertNotNull(f);

    e.decodeField(f, o, new Attribute("foo", "malformed"));
  }



  /**
   * Provides test coverage for the {@code decodeField} method for a malformed
   * Date value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldMalformedDate()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("dateF");
    assertNotNull(f);

    e.decodeField(f, o, new Attribute("foo", "malformed"));
  }



  /**
   * Provides test coverage for the {@code decodeField} method for a malformed
   * DN value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldMalformedDN()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("dnF");
    assertNotNull(f);

    e.decodeField(f, o, new Attribute("foo", "malformed"));
  }



  /**
   * Provides test coverage for the {@code decodeField} method for a malformed
   * Filter value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldMalformedFilter()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("filterF");
    assertNotNull(f);

    e.decodeField(f, o, new Attribute("foo", "malformed"));
  }



  /**
   * Provides test coverage for the {@code decodeField} method for a malformed
   * FilterUsage value.  This will cover functionality for all enum types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldMalformedFilterUsage()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("filterUsageF");
    assertNotNull(f);

    e.decodeField(f, o, new Attribute("foo", "malformed"));
  }



  /**
   * Provides test coverage for the {@code decodeField} method for a malformed
   * LDAPURL value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldMalformedLDAPURL()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("ldapURLF");
    assertNotNull(f);

    e.decodeField(f, o, new Attribute("foo", "malformed"));
  }



  /**
   * Provides test coverage for the {@code decodeField} method for a malformed
   * RDN value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldMalformedRDN()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("rdnF");
    assertNotNull(f);

    e.decodeField(f, o, new Attribute("foo", "malformed"));
  }



  /**
   * Provides test coverage for the {@code decodeField} method for a malformed
   * URI value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldMalformedURI()
       throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("uriF");
    assertNotNull(f);

    e.decodeField(f, o, new Attribute("foo", "://malformed"));
  }



  /**
   * Provides test coverage for the {@code decodeField} method for a malformed
   * URL value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldMalformedURL()
       throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("urlF");
    assertNotNull(f);

    e.decodeField(f, o, new Attribute("foo", "://malformed"));
  }



  /**
   * Provides test coverage for the {@code decodeField} method for a malformed
   * UUID value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldMalformedUUID()
       throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("uuidF");
    assertNotNull(f);

    e.decodeField(f, o, new Attribute("foo", "malformed"));
  }



  /**
   * Provides test coverage for the {@code decodeField} method for a field
   * with an unsupported type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldUnsupportedType()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultEncoderUnsupportedType o =
         new TestDefaultEncoderUnsupportedType();

    Field f = o.getClass().getDeclaredField("fieldValue");
    assertNotNull(f);

    e.decodeField(f, o, new Attribute("foo", "bar"));
  }



  /**
   * Provides test coverage for the {@code decodeField} method for a field
   * with an unsupported array type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldUnsupportedArrayType()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultEncoderUnsupportedType o =
         new TestDefaultEncoderUnsupportedType();

    Field f = o.getClass().getDeclaredField("fieldArrayValue");
    assertNotNull(f);

    e.decodeField(f, o, new Attribute("foo", "bar"));
  }



  /**
   * Provides test coverage for the {@code decodeField} method when provided
   * with a null attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testDecodeFieldNullAttribute()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultEncoderUnsupportedType o =
         new TestDefaultEncoderUnsupportedType();

    Field f = o.getClass().getDeclaredField("fieldArrayValue");
    assertNotNull(f);

    e.decodeField(f, o, null);
  }



  /**
   * Provides test coverage for the {@code invokeSetter} method with a malformed
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testInvokeSetterMalformedValue()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setBooleanPF", Boolean.TYPE);
    assertNotNull(m);

    e.invokeSetter(m, o, new Attribute("foo", "bar"));
  }



  /**
   * Provides test coverage for the {@code invokeSetter} method for an object
   * with an unsupported type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testInvokeSetterInvalidType()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultEncoderUnsupportedType o =
         new TestDefaultEncoderUnsupportedType();

    Method m = o.getClass().getDeclaredMethod("setMethodValue", Object.class);
    assertNotNull(m);

    e.invokeSetter(m, o, new Attribute("foo", "bar"));
  }



  /**
   * Provides test coverage for the {@code invokeSetter} method for an object
   * with an unsupported array type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testInvokeSetterInvalidArrayType()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultEncoderUnsupportedType o =
         new TestDefaultEncoderUnsupportedType();

    Object[] array = new Object[] { new Object() };

    Method m = o.getClass().getDeclaredMethod("setMethodArrayValue",
         array.getClass());
    assertNotNull(m);

    e.invokeSetter(m, o, new Attribute("foo", "bar", "baz"));
  }



  /**
   * Provides test coverage for the {@code invokeSetter} method with a null
   * attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testInvokeSetterNullAttribute()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("setBooleanPF", Boolean.TYPE);
    assertNotNull(m);

    e.invokeSetter(m, o, null);
  }



  /**
   * Provides test coverage for the {@code supportsMultipleValues} method with a
   * method that does not take any arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSupportsMultipleValuesNoArgumentMethod()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Method m = o.getClass().getDeclaredMethod("getBooleanPF");
    assertNotNull(m);

    assertFalse(e.supportsMultipleValues(m));
  }



  /**
   * Provides test coverage for the {@code setNull} method for a boolean
   * primitive field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullBooleanField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertFalse(o.getBooleanF());

    o.setBooleanF(true);
    assertTrue(o.getBooleanF());

    Field f = o.getClass().getDeclaredField("booleanF");
    assertNotNull(f);

    e.setNull(f, o);
    assertFalse(o.getBooleanF());
  }



  /**
   * Provides test coverage for the {@code setNull} method for a byte
   * primitive field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullByteField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getByteF(), (byte) 0x00);

    o.setByteF((byte) 0x01);
    assertEquals(o.getByteF(), (byte) 0x01);

    Field f = o.getClass().getDeclaredField("byteF");
    assertNotNull(f);

    e.setNull(f, o);
    assertEquals(o.getByteF(), (byte) 0x00);
  }



  /**
   * Provides test coverage for the {@code setNull} method for a char
   * primitive field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullCharField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getCharF(), (byte) '\u0000');

    o.setCharF('a');
    assertEquals(o.getCharF(), 'a');

    Field f = o.getClass().getDeclaredField("charF");
    assertNotNull(f);

    e.setNull(f, o);
    assertEquals(o.getCharF(), '\u0000');
  }



  /**
   * Provides test coverage for the {@code setNull} method for a double
   * primitive field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullDoubleField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getDoubleF(), 0.0d);

    o.setDoubleF(1.25d);
    assertEquals(o.getDoubleF(), 1.25d);

    Field f = o.getClass().getDeclaredField("doubleF");
    assertNotNull(f);

    e.setNull(f, o);
    assertEquals(o.getDoubleF(), 0.00d);
  }



  /**
   * Provides test coverage for the {@code setNull} method for a float
   * primitive field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullFloatField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getFloatF(), 0.0f);

    o.setFloatF(1.25f);
    assertEquals(o.getFloatF(), 1.25f);

    Field f = o.getClass().getDeclaredField("floatF");
    assertNotNull(f);

    e.setNull(f, o);
    assertEquals(o.getFloatF(), 0.00f);
  }



  /**
   * Provides test coverage for the {@code setNull} method for a int
   * primitive field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullIntField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getIntF(), 0);

    o.setIntF(1234);
    assertEquals(o.getIntF(), 1234);

    Field f = o.getClass().getDeclaredField("intF");
    assertNotNull(f);

    e.setNull(f, o);
    assertEquals(o.getIntF(), 0);
  }



  /**
   * Provides test coverage for the {@code setNull} method for a long
   * primitive field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullLongField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getLongF(), 0L);

    o.setLongF(1234L);
    assertEquals(o.getLongF(), 1234L);

    Field f = o.getClass().getDeclaredField("longF");
    assertNotNull(f);

    e.setNull(f, o);
    assertEquals(o.getLongF(), 0L);
  }



  /**
   * Provides test coverage for the {@code setNull} method for a short
   * primitive field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullShortField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getShortF(), (short) 0);

    o.setShortF((short) 1234);
    assertEquals(o.getShortF(), (short) 1234);

    Field f = o.getClass().getDeclaredField("shortF");
    assertNotNull(f);

    e.setNull(f, o);
    assertEquals(o.getShortF(), (short) 0);
  }



  /**
   * Provides test coverage for the {@code setNull} method for an Object field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullObjectField()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertNull(o.getObjectF());

    o.setObjectF(new Object());
    assertNotNull(o.getObjectF());

    Field f = o.getClass().getDeclaredField("objectF");
    assertNotNull(f);

    e.setNull(f, o);
    assertNull(o.getObjectF());
  }



  /**
   * Provides test coverage for the {@code setNull} method with an exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testSetNullFieldWithException()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    Field f = o.getClass().getDeclaredField("objectF");
    assertNotNull(f);

    e.setNull(f, new Object()); // Setting it on the wrong object.
  }



  /**
   * Provides test coverage for the {@code setNull} method for a setter that
   * takes a boolean primitive argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullBooleanMethod()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertFalse(o.getBooleanMF());

    o.setBooleanMF(true);
    assertTrue(o.getBooleanMF());

    Method m = o.getClass().getDeclaredMethod("setBooleanMF", Boolean.TYPE);
    assertNotNull(m);

    e.setNull(m, o);
    assertFalse(o.getBooleanMF());
  }



  /**
   * Provides test coverage for the {@code setNull} method for a setter that
   * takes a byte primitive argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullByteMethod()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getByteMF(), (byte) 0x00);

    o.setByteMF((byte) 0x01);
    assertEquals(o.getByteMF(), (byte) 0x01);

    Method m = o.getClass().getDeclaredMethod("setByteMF", Byte.TYPE);
    assertNotNull(m);

    e.setNull(m, o);
    assertEquals(o.getByteMF(), (byte) 0x00);
  }



  /**
   * Provides test coverage for the {@code setNull} method for a setter that
   * takes a char primitive argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullCharMethod()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getCharMF(), (byte) '\u0000');

    o.setCharMF('a');
    assertEquals(o.getCharMF(), 'a');

    Method m = o.getClass().getDeclaredMethod("setCharMF", Character.TYPE);
    assertNotNull(m);

    e.setNull(m, o);
    assertEquals(o.getCharMF(), '\u0000');
  }



  /**
   * Provides test coverage for the {@code setNull} method for a setter that
   * takes a double primitive argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullDoubleMethod()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getDoubleMF(), 0.0d);

    o.setDoubleMF(1.25d);
    assertEquals(o.getDoubleMF(), 1.25d);

    Method m = o.getClass().getDeclaredMethod("setDoubleMF", Double.TYPE);
    assertNotNull(m);

    e.setNull(m, o);
    assertEquals(o.getDoubleMF(), 0.00d);
  }



  /**
   * Provides test coverage for the {@code setNull} method for a setter that
   * takes a float primitive argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullFloatMethod()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getFloatMF(), 0.0f);

    o.setFloatMF(1.25f);
    assertEquals(o.getFloatMF(), 1.25f);

    Method m = o.getClass().getDeclaredMethod("setFloatMF", Float.TYPE);
    assertNotNull(m);

    e.setNull(m, o);
    assertEquals(o.getFloatMF(), 0.00f);
  }



  /**
   * Provides test coverage for the {@code setNull} method for a setter that
   * takes an int primitive argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullIntMethod()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getIntMF(), 0);

    o.setIntMF(1234);
    assertEquals(o.getIntMF(), 1234);

    Method m = o.getClass().getDeclaredMethod("setIntMF", Integer.TYPE);
    assertNotNull(m);

    e.setNull(m, o);
    assertEquals(o.getIntMF(), 0);
  }



  /**
   * Provides test coverage for the {@code setNull} method for a setter that
   * takes a long primitive argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullLong()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getLongMF(), 0L);

    o.setLongMF(1234L);
    assertEquals(o.getLongMF(), 1234L);

    Method m = o.getClass().getDeclaredMethod("setLongMF", Long.TYPE);
    assertNotNull(m);

    e.setNull(m, o);
    assertEquals(o.getLongMF(), 0L);
  }



  /**
   * Provides test coverage for the {@code setNull} method for a setter that
   * takes a short primitive argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullShortMethod()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertEquals(o.getShortMF(), (short) 0);

    o.setShortMF((short) 1234);
    assertEquals(o.getShortMF(), (short) 1234);

    Method m = o.getClass().getDeclaredMethod("setShortMF", Short.TYPE);
    assertNotNull(m);

    e.setNull(m, o);
    assertEquals(o.getShortMF(), (short) 0);
  }



  /**
   * Provides test coverage for the {@code setNull} method for a setter that
   * takes an Object argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetNullObjectMethod()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    assertNull(o.getObjectMF());

    o.setObjectMF(new Object());
    assertNotNull(o.getObjectMF());

    Method m = o.getClass().getDeclaredMethod("setObjectMF", Object.class);
    assertNotNull(m);

    e.setNull(m, o);
    assertNull(o.getObjectMF());
  }



  /**
   * Provides test coverage for the {@code setNull} method with an exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testSetNullMethodWithException()
         throws Exception
  {
    DefaultObjectEncoder e = new DefaultObjectEncoder();

    TestNullable o = new TestNullable();

    Method m = o.getClass().getDeclaredMethod("setObjectMF", Object.class);
    assertNotNull(m);

    e.setNull(m, new Object()); // Setting it on the wrong object.
  }



  /**
   * Tests the behavior of the default object encoder with regard to
   * serializable objects.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSerializable()
         throws Exception
  {
    // Calendar objects are serializable but not directly supported by the
    // default object encoder, so they'll make a good test case.
    final GregorianCalendar c = new GregorianCalendar();
    assertTrue(c instanceof Serializable);

    final DefaultObjectEncoder e = new DefaultObjectEncoder();
    assertTrue(e.supportsType(c.getClass()));

    final TestDefaultObjectEncoderValidObject o =
         new TestDefaultObjectEncoderValidObject();

    Field f = o.getClass().getDeclaredField("gregorianCalendarF");
    assertNotNull(f);

    Attribute a = e.encodeFieldValue(f, c, "gregorianCalendarF");

    assertNull(o.getGregorianCalendarF());
    e.decodeField(f, o, a);
    assertNotNull(o.getGregorianCalendarF());
    assertEquals(o.getGregorianCalendarF(), c);


    f = o.getClass().getDeclaredField("gregorianCalendarAF");
    assertNotNull(f);

    final GregorianCalendar[] ca = { c };
    a = e.encodeFieldValue(f, ca, "gregorianCalendarAF");

    assertNull(o.getGregorianCalendarAF());
    e.decodeField(f, o, a);
    assertNotNull(o.getGregorianCalendarAF());
    assertEquals(o.getGregorianCalendarAF(), ca);


    f = o.getClass().getDeclaredField("gregorianCalendarArrayListF");
    assertNotNull(f);

    final ArrayList<GregorianCalendar> cl = new ArrayList<GregorianCalendar>(1);
    cl.add(c);
    a = e.encodeFieldValue(f, cl, "gregorianCalendarArrayListF");

    assertNull(o.getGregorianCalendarArrayListF());
    e.decodeField(f, o, a);
    assertNotNull(o.getGregorianCalendarArrayListF());
    assertEquals(o.getGregorianCalendarArrayListF(), cl);


    f = o.getClass().getDeclaredField("gregorianCalendarHashSetF");
    assertNotNull(f);

    final HashSet<GregorianCalendar> cs = new HashSet<GregorianCalendar>(1);
    cs.add(c);
    a = e.encodeFieldValue(f, cs, "gregorianCalendarHashSetF");

    assertNull(o.getGregorianCalendarHashSetF());
    e.decodeField(f, o, a);
    assertNotNull(o.getGregorianCalendarHashSetF());
    assertEquals(o.getGregorianCalendarHashSetF(), cs);
  }
}
