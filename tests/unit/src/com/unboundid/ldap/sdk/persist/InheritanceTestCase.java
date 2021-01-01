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
package com.unboundid.ldap.sdk.persist;



import java.util.Arrays;
import java.util.HashSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for object inheritance.
 */
public final class InheritanceTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a test with the top-level class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testL1()
         throws Exception
  {
    final LDAPPersister<TestInheritanceL1> p =
         LDAPPersister.getInstance(TestInheritanceL1.class);

    final TestInheritanceL1 o = new TestInheritanceL1();

    o.setRequiredL1("r1");
    o.setOptionalL1("o1");

    assertNull(o.getL1Entry());
    assertNull(p.getObjectHandler().getEntryDN(o));
    assertNull(p.getObjectHandler().getEntry(o));

    Entry e = p.encode(o, null);

    assertNotNull(e);

    assertNotNull(e.getDN());
    assertEquals(new DN(e.getDN()),
         new DN("requiredL1=r1,dc=example,dc=com"));

    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL1"));

    assertTrue(e.hasAttributeValue("requiredL1", "r1"));

    assertTrue(e.hasAttributeValue("optionalL1", "o1"));

    assertNotNull(o.getL1Entry());
    assertNotNull(p.getObjectHandler().getEntryDN(o));
    assertNotNull(p.getObjectHandler().getEntry(o));
    assertDNsEqual(p.getObjectHandler().getEntryDN(o),
         "requiredL1=r1,dc=example,dc=com");

    final TestInheritanceL1 decoded = p.decode(new Entry(
         "dn: requiredL1=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testInheritanceL1",
         "requiredL1: testRequired1",
         "optionalL1: testOptional1"));

    assertNotNull(decoded);

    assertEquals(decoded.getRequiredL1(), "testRequired1");

    assertEquals(decoded.getOptionalL1(), "testOptional1");

    assertNotNull(decoded.getL1Entry());
    assertNotNull(p.getObjectHandler().getEntryDN(decoded));
    assertNotNull(p.getObjectHandler().getEntry(decoded));
    assertDNsEqual(p.getObjectHandler().getEntryDN(decoded),
         "requiredL1=test,dc=example,dc=com");

    assertHasAttributesToRequest(p, "requiredL1", "optionalL1");
  }



  /**
   * Performs a test with a single level of inheritance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testL2()
         throws Exception
  {
    final LDAPPersister<TestInheritanceL2> p =
         LDAPPersister.getInstance(TestInheritanceL2.class);

    final TestInheritanceL2 o = new TestInheritanceL2();

    o.setRequiredL1("r1");
    o.setOptionalL1("o1");
    o.setRequiredL2("r2");
    o.setOptionalL2("o2");

    assertNull(o.getL1Entry());
    assertNull(o.getL2DN());
    assertNull(p.getObjectHandler().getEntryDN(o));
    assertNull(p.getObjectHandler().getEntry(o));

    final Entry e = p.encode(o, null);

    assertNotNull(e);

    assertNotNull(e.getDN());
    assertEquals(new DN(e.getDN()),
         new DN("requiredL2=r2,dc=example,dc=com"));

    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL1"));
    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL2"));

    assertTrue(e.hasAttributeValue("requiredL1", "r1"));

    assertTrue(e.hasAttributeValue("optionalL1", "o1"));

    assertTrue(e.hasAttributeValue("requiredL2", "r2"));

    assertTrue(e.hasAttributeValue("optionalL2", "o2"));

    assertNotNull(o.getL1Entry());
    assertNotNull(o.getL2DN());
    assertNotNull(p.getObjectHandler().getEntryDN(o));
    assertNotNull(p.getObjectHandler().getEntry(o));
    assertDNsEqual(p.getObjectHandler().getEntryDN(o),
         "requiredL2=r2,dc=example,dc=com");


    final TestInheritanceL2 decoded = p.decode(new Entry(
         "dn: requiredL2=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testInheritanceL1",
         "objectClass: testInheritanceL2",
         "requiredL1: testRequired1",
         "optionalL1: testOptional1",
         "requiredL2: testRequired2",
         "optionalL2: testOptional2"));

    assertNotNull(decoded);

    assertEquals(decoded.getRequiredL1(), "testRequired1");

    assertEquals(decoded.getOptionalL1(), "testOptional1");

    assertEquals(decoded.getRequiredL2(), "testRequired2");

    assertEquals(decoded.getOptionalL2(), "testOptional2");

    assertNotNull(decoded.getL1Entry());
    assertNotNull(decoded.getL2DN());
    assertNotNull(p.getObjectHandler().getEntryDN(decoded));
    assertNotNull(p.getObjectHandler().getEntry(decoded));
    assertDNsEqual(p.getObjectHandler().getEntryDN(decoded),
         "requiredL2=test,dc=example,dc=com");

    assertHasAttributesToRequest(p, "requiredL1", "optionalL1", "requiredL2",
         "optionalL2");
  }



  /**
   * Performs a test with a single level of inheritance in which a required
   * superclass field was not provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testL2EncodeMissingSuperclassField()
         throws Exception
  {
    final LDAPPersister<TestInheritanceL2> p =
         LDAPPersister.getInstance(TestInheritanceL2.class);

    final TestInheritanceL2 o = new TestInheritanceL2();

    o.setOptionalL1("o1");
    o.setRequiredL2("r2");
    o.setOptionalL2("o2");

    try
    {
      p.encode(o, null);
      fail("Expected an exception because of a missing required1 field");
    }
    catch (final LDAPPersistException lpe)
    {
      // This was expected
    }

    o.setRequiredL1("r1");
    final Entry e = p.encode(o, null);

    assertNotNull(e);

    assertNotNull(e.getDN());
    assertEquals(new DN(e.getDN()),
         new DN("requiredL2=r2,dc=example,dc=com"));

    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL1"));
    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL2"));

    assertTrue(e.hasAttributeValue("requiredL1", "r1"));

    assertTrue(e.hasAttributeValue("optionalL1", "o1"));

    assertTrue(e.hasAttributeValue("requiredL2", "r2"));

    assertTrue(e.hasAttributeValue("optionalL2", "o2"));


    final Entry entryToDecode = new Entry(
         "dn: requiredL2=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testInheritanceL1",
         "objectClass: testInheritanceL2",
         "optionalL1: testOptional1",
         "requiredL2: testRequired2",
         "optionalL2: testOptional2");

    try
    {
      p.decode(entryToDecode);
      fail("Expected an exception because of a missing required1 attribute");
    }
    catch (final LDAPPersistException lpe)
    {
      // This was expected
    }

    entryToDecode.addAttribute("requiredL1", "testRequired1");
    final TestInheritanceL2 decoded = p.decode(entryToDecode);

    assertNotNull(decoded);

    assertEquals(decoded.getRequiredL1(), "testRequired1");

    assertEquals(decoded.getOptionalL1(), "testOptional1");

    assertEquals(decoded.getRequiredL2(), "testRequired2");

    assertEquals(decoded.getOptionalL2(), "testOptional2");
  }



  /**
   * Performs a test with two levels of inheritance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testL3()
         throws Exception
  {
    final LDAPPersister<TestInheritanceL3> p =
         LDAPPersister.getInstance(TestInheritanceL3.class);

    final TestInheritanceL3 o = new TestInheritanceL3();

    o.setRequiredL1("r1");
    o.setOptionalL1("o1");
    o.setRequiredL2("r2");
    o.setOptionalL2("o2");
    o.setRequiredL3("r3");
    o.setOptionalL3("o3");

    assertNull(o.getL1Entry());
    assertNull(o.getL2DN());
    assertNull(p.getObjectHandler().getEntryDN(o));
    assertNull(p.getObjectHandler().getEntry(o));

    final int l3BeforeEncodeCount =
         TestInheritanceL3.getL3PostEncodeInvokeCount();
    final int l4BeforeEncodeCount =
         TestInheritanceL4.getL4PostEncodeInvokeCount();

    final Entry e = p.encode(o, null);

    final int l3AfterEncodeCount =
         TestInheritanceL3.getL3PostEncodeInvokeCount();
    final int l4AfterEncodeCount =
         TestInheritanceL4.getL4PostEncodeInvokeCount();
    assertEquals(l3AfterEncodeCount, (l3BeforeEncodeCount+1));
    assertEquals(l4AfterEncodeCount, l4BeforeEncodeCount);

    assertNotNull(e);

    assertNotNull(e.getDN());
    assertEquals(new DN(e.getDN()),
         new DN("requiredL3=r3,dc=example,dc=com"));

    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL1"));
    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL2"));
    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL3"));

    assertTrue(e.hasAttributeValue("requiredL1", "r1"));

    assertTrue(e.hasAttributeValue("optionalL1", "o1"));

    assertTrue(e.hasAttributeValue("requiredL2", "r2"));

    assertTrue(e.hasAttributeValue("optionalL2", "o2"));

    assertTrue(e.hasAttributeValue("requiredL3", "r3"));

    assertTrue(e.hasAttributeValue("optionalL3", "o3"));

    assertNotNull(o.getL1Entry());
    assertNotNull(o.getL2DN());
    assertNotNull(p.getObjectHandler().getEntryDN(o));
    assertNotNull(p.getObjectHandler().getEntry(o));
    assertDNsEqual(p.getObjectHandler().getEntryDN(o),
         "requiredL3=r3,dc=example,dc=com");


    final int l3BeforeDecodeCount =
         TestInheritanceL3.getL3PostDecodeInvokeCount();
    final int l4BeforeDecodeCount =
         TestInheritanceL4.getL4PostDecodeInvokeCount();

    final TestInheritanceL3 decoded = p.decode(new Entry(
         "dn: requiredL2=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testInheritanceL1",
         "objectClass: testInheritanceL2",
         "objectClass: testInheritanceL3",
         "requiredL1: testRequired1",
         "optionalL1: testOptional1",
         "requiredL2: testRequired2",
         "optionalL2: testOptional2",
         "requiredL3: testRequired3",
         "optionalL3: testOptional3"));

    final int l3AfterDecodeCount =
         TestInheritanceL3.getL3PostDecodeInvokeCount();
    final int l4AfterDecodeCount =
         TestInheritanceL4.getL4PostDecodeInvokeCount();
    assertEquals(l3AfterDecodeCount, (l3BeforeDecodeCount+1));
    assertEquals(l4AfterDecodeCount, l4BeforeDecodeCount);

    assertNotNull(decoded);

    assertEquals(decoded.getRequiredL1(), "testRequired1");

    assertEquals(decoded.getOptionalL1(), "testOptional1");

    assertEquals(decoded.getRequiredL2(), "testRequired2");

    assertEquals(decoded.getOptionalL2(), "testOptional2");

    assertEquals(decoded.getRequiredL3(), "testRequired3");

    assertEquals(decoded.getOptionalL3(), "testOptional3");

    assertNotNull(decoded.getL1Entry());
    assertNotNull(decoded.getL2DN());
    assertNotNull(p.getObjectHandler().getEntryDN(decoded));
    assertNotNull(p.getObjectHandler().getEntry(decoded));
    assertDNsEqual(p.getObjectHandler().getEntryDN(decoded),
         "requiredL2=test,dc=example,dc=com");

    assertHasAttributesToRequest(p, "*", "+");
  }



  /**
   * Performs a test with two levels of inheritance in which a required
   * superclass field was not provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testL3EncodeMissingSuperclassField()
         throws Exception
  {
    final LDAPPersister<TestInheritanceL3> p =
         LDAPPersister.getInstance(TestInheritanceL3.class);

    final TestInheritanceL3 o = new TestInheritanceL3();

    o.setOptionalL1("o1");
    o.setRequiredL1("r1");
    o.setOptionalL2("o2");
    o.setRequiredL3("r3");
    o.setOptionalL3("o3");

    try
    {
      p.encode(o, null);
      fail("Expected an exception because of a missing required1 field");
    }
    catch (final LDAPPersistException lpe)
    {
      // This was expected
    }

    o.setRequiredL2("r2");
    final Entry e = p.encode(o, null);

    assertNotNull(e);

    assertNotNull(e.getDN());
    assertEquals(new DN(e.getDN()),
         new DN("requiredL3=r3,dc=example,dc=com"));

    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL1"));
    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL2"));
    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL3"));

    assertTrue(e.hasAttributeValue("requiredL1", "r1"));

    assertTrue(e.hasAttributeValue("optionalL1", "o1"));

    assertTrue(e.hasAttributeValue("requiredL2", "r2"));

    assertTrue(e.hasAttributeValue("optionalL2", "o2"));

    assertTrue(e.hasAttributeValue("requiredL3", "r3"));

    assertTrue(e.hasAttributeValue("optionalL3", "o3"));


    final Entry entryToDecode = new Entry(
         "dn: requiredL2=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testInheritanceL1",
         "objectClass: testInheritanceL2",
         "objectClass: testInheritanceL3",
         "optionalL1: testOptional1",
         "requiredL1: testRequired1",
         "optionalL2: testOptional2",
         "requiredL3: testRequired3",
         "optionalL3: testOptional3");

    try
    {
      p.decode(entryToDecode);
      fail("Expected an exception because of a missing required1 attribute");
    }
    catch (final LDAPPersistException lpe)
    {
      // This was expected
    }

    entryToDecode.addAttribute("requiredL2", "testRequired2");
    final TestInheritanceL3 decoded = p.decode(entryToDecode);

    assertNotNull(decoded);

    assertEquals(decoded.getRequiredL1(), "testRequired1");

    assertEquals(decoded.getOptionalL1(), "testOptional1");

    assertEquals(decoded.getRequiredL2(), "testRequired2");

    assertEquals(decoded.getOptionalL2(), "testOptional2");

    assertEquals(decoded.getRequiredL3(), "testRequired3");

    assertEquals(decoded.getOptionalL3(), "testOptional3");
  }



  /**
   * Performs a test with two levels of inheritance in which a required
   * top-level class field was not provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testL3EncodeMissingSuperSuperclassField()
         throws Exception
  {
    final LDAPPersister<TestInheritanceL3> p =
         LDAPPersister.getInstance(TestInheritanceL3.class);

    final TestInheritanceL3 o = new TestInheritanceL3();

    o.setOptionalL1("o1");
    o.setRequiredL2("r2");
    o.setOptionalL2("o2");
    o.setRequiredL3("r3");
    o.setOptionalL3("o3");

    try
    {
      p.encode(o, null);
      fail("Expected an exception because of a missing required1 field");
    }
    catch (final LDAPPersistException lpe)
    {
      // This was expected
    }

    o.setRequiredL1("r1");
    final Entry e = p.encode(o, null);

    assertNotNull(e);

    assertNotNull(e.getDN());
    assertEquals(new DN(e.getDN()),
         new DN("requiredL3=r3,dc=example,dc=com"));

    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL1"));
    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL2"));
    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL3"));

    assertTrue(e.hasAttributeValue("requiredL1", "r1"));

    assertTrue(e.hasAttributeValue("optionalL1", "o1"));

    assertTrue(e.hasAttributeValue("requiredL2", "r2"));

    assertTrue(e.hasAttributeValue("optionalL2", "o2"));

    assertTrue(e.hasAttributeValue("requiredL3", "r3"));

    assertTrue(e.hasAttributeValue("optionalL3", "o3"));


    final Entry entryToDecode = new Entry(
         "dn: requiredL2=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testInheritanceL1",
         "objectClass: testInheritanceL2",
         "objectClass: testInheritanceL3",
         "optionalL1: testOptional1",
         "requiredL2: testRequired2",
         "optionalL2: testOptional2",
         "requiredL3: testRequired3",
         "optionalL3: testOptional3");

    try
    {
      p.decode(entryToDecode);
      fail("Expected an exception because of a missing required1 attribute");
    }
    catch (final LDAPPersistException lpe)
    {
      // This was expected
    }

    entryToDecode.addAttribute("requiredL1", "testRequired1");
    final TestInheritanceL3 decoded = p.decode(entryToDecode);

    assertNotNull(decoded);

    assertEquals(decoded.getRequiredL1(), "testRequired1");

    assertEquals(decoded.getOptionalL1(), "testOptional1");

    assertEquals(decoded.getRequiredL2(), "testRequired2");

    assertEquals(decoded.getOptionalL2(), "testOptional2");

    assertEquals(decoded.getRequiredL3(), "testRequired3");

    assertEquals(decoded.getOptionalL3(), "testOptional3");
  }



  /**
   * Performs a test with three levels of inheritance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testL4()
         throws Exception
  {
    final LDAPPersister<TestInheritanceL4> p =
         LDAPPersister.getInstance(TestInheritanceL4.class);

    final TestInheritanceL4 o = new TestInheritanceL4();

    o.setRequiredL1("r1");
    o.setOptionalL1("o1");
    o.setRequiredL2("r2");
    o.setOptionalL2("o2");
    o.setRequiredL3("r3");
    o.setOptionalL3("o3");
    o.setRequiredL4("r4");
    o.setOptionalL4("o4");

    assertNull(o.getL1Entry());
    assertNull(o.getL2DN());
    assertNull(p.getObjectHandler().getEntryDN(o));
    assertNull(p.getObjectHandler().getEntry(o));

    final int l3BeforeEncodeCount =
         TestInheritanceL3.getL3PostEncodeInvokeCount();
    final int l4BeforeEncodeCount =
         TestInheritanceL4.getL4PostEncodeInvokeCount();

    final Entry e = p.encode(o, null);

    final int l3AfterEncodeCount =
         TestInheritanceL3.getL3PostEncodeInvokeCount();
    final int l4AfterEncodeCount =
         TestInheritanceL4.getL4PostEncodeInvokeCount();
    assertEquals(l3AfterEncodeCount, (l3BeforeEncodeCount+1));
    assertEquals(l4AfterEncodeCount, (l4BeforeEncodeCount+1));

    assertNotNull(e);

    assertNotNull(e.getDN());
    assertEquals(new DN(e.getDN()),
         new DN("requiredL3=r3,dc=example,dc=com"));

    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL1"));
    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL2"));
    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL3"));
    assertTrue(e.hasAttributeValue("objectClass", "testInheritanceL4"));

    assertTrue(e.hasAttributeValue("requiredL1", "r1"));

    assertTrue(e.hasAttributeValue("optionalL1", "o1"));

    assertTrue(e.hasAttributeValue("requiredL2", "r2"));

    assertTrue(e.hasAttributeValue("optionalL2", "o2"));

    assertTrue(e.hasAttributeValue("requiredL3", "r3"));

    assertTrue(e.hasAttributeValue("optionalL3", "o3"));

    assertTrue(e.hasAttributeValue("requiredL4", "r4"));

    assertTrue(e.hasAttributeValue("optionalL4", "o4"));

    assertNotNull(o.getL1Entry());
    assertNotNull(o.getL2DN());
    assertNotNull(p.getObjectHandler().getEntryDN(o));
    assertNotNull(p.getObjectHandler().getEntry(o));
    assertDNsEqual(p.getObjectHandler().getEntryDN(o),
         "requiredL3=r3,dc=example,dc=com");


    final int l3BeforeDecodeCount =
         TestInheritanceL3.getL3PostDecodeInvokeCount();
    final int l4BeforeDecodeCount =
         TestInheritanceL4.getL4PostDecodeInvokeCount();

    final TestInheritanceL4 decoded = p.decode(new Entry(
         "dn: requiredL4=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testInheritanceL1",
         "objectClass: testInheritanceL2",
         "objectClass: testInheritanceL3",
         "objectClass: testInheritanceL4",
         "requiredL1: testRequired1",
         "optionalL1: testOptional1",
         "requiredL2: testRequired2",
         "optionalL2: testOptional2",
         "requiredL3: testRequired3",
         "optionalL3: testOptional3",
         "requiredL4: testRequired4",
         "optionalL4: testOptional4"));

    assertNotNull(decoded);

    final int l3AfterDecodeCount =
         TestInheritanceL3.getL3PostDecodeInvokeCount();
    final int l4AfterDecodeCount =
         TestInheritanceL4.getL4PostDecodeInvokeCount();
    assertEquals(l3AfterDecodeCount, (l3BeforeDecodeCount+1));
    assertEquals(l4AfterDecodeCount, (l4BeforeDecodeCount+1));

    assertEquals(decoded.getRequiredL1(), "testRequired1");

    assertEquals(decoded.getOptionalL1(), "testOptional1");

    assertEquals(decoded.getRequiredL2(), "testRequired2");

    assertEquals(decoded.getOptionalL2(), "testOptional2");

    assertEquals(decoded.getRequiredL3(), "testRequired3");

    assertEquals(decoded.getOptionalL3(), "testOptional3");

    assertEquals(decoded.getRequiredL4(), "testRequired4");

    assertEquals(decoded.getOptionalL4(), "testOptional4");

    assertNotNull(decoded.getL1Entry());
    assertNotNull(decoded.getL2DN());
    assertNotNull(p.getObjectHandler().getEntryDN(decoded));
    assertNotNull(p.getObjectHandler().getEntry(decoded));
    assertDNsEqual(p.getObjectHandler().getEntryDN(decoded),
         "requiredL4=test,dc=example,dc=com");

    assertHasAttributesToRequest(p, "*", "+");
  }



  /**
   * Tests to ensure that filters can be handled properly for objects using
   * inheritance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterInheritance()
         throws Exception
  {
    final LDAPPersister<TestInheritanceL3> p =
         LDAPPersister.getInstance(TestInheritanceL3.class);


    // First, test with an object that only includes direct members.
    TestInheritanceL3 o = new TestInheritanceL3();
    o.setRequiredL3("a");

    Filter f = p.getObjectHandler().createFilter(o);
    assertNotNull(f);
    assertTrue(Arrays.asList(f.getComponents()).contains(
         Filter.createEqualityFilter("requiredL3", "a")));
    assertFalse(Arrays.asList(f.getComponents()).contains(
         Filter.createEqualityFilter("requiredL2", "b")));
    assertFalse(Arrays.asList(f.getComponents()).contains(
         Filter.createEqualityFilter("requiredL1", "c")));


    // Second, test with an object that only includes members from the immediate
    // superclass.
    o = new TestInheritanceL3();
    o.setRequiredL2("b");

    f = p.getObjectHandler().createFilter(o);
    assertNotNull(f);
    assertFalse(Arrays.asList(f.getComponents()).contains(
         Filter.createEqualityFilter("requiredL3", "a")));
    assertTrue(Arrays.asList(f.getComponents()).contains(
         Filter.createEqualityFilter("requiredL2", "b")));
    assertFalse(Arrays.asList(f.getComponents()).contains(
         Filter.createEqualityFilter("requiredL1", "c")));


    // Third, test with an object that only includes members from a
    // non-immediate superclass.
    o = new TestInheritanceL3();
    o.setRequiredL1("c");

    f = p.getObjectHandler().createFilter(o);
    assertNotNull(f);
    assertFalse(Arrays.asList(f.getComponents()).contains(
         Filter.createEqualityFilter("requiredL3", "a")));
    assertFalse(Arrays.asList(f.getComponents()).contains(
         Filter.createEqualityFilter("requiredL2", "b")));
    assertTrue(Arrays.asList(f.getComponents()).contains(
         Filter.createEqualityFilter("requiredL1", "c")));


    // Finally, test with an object that only includes members from multiple
    // inheritance levels.
    o = new TestInheritanceL3();
    o.setRequiredL3("a");
    o.setRequiredL2("b");
    o.setRequiredL1("c");

    f = p.getObjectHandler().createFilter(o);
    assertNotNull(f);
    assertTrue(Arrays.asList(f.getComponents()).contains(
         Filter.createEqualityFilter("requiredL3", "a")));
    assertTrue(Arrays.asList(f.getComponents()).contains(
         Filter.createEqualityFilter("requiredL2", "b")));
    assertTrue(Arrays.asList(f.getComponents()).contains(
         Filter.createEqualityFilter("requiredL1", "c")));
  }



  /**
   * Ensures that the provided persister instance will request all of the
   * specified attribute types.
   *
   * @param  p      The persister instance to validate.
   * @param  attrs  The names of the attributes expected to be included in the
   *                set of attributes to request.
   *
   * @throws  AssertionError  If any of the specified attributes is not included
   *                          in the set of attributes to request.
   */
  private static void assertHasAttributesToRequest(final LDAPPersister<?> p,
                                                   final String... attrs)
          throws AssertionError
  {
    final String[] attrsToRequest =
         p.getObjectHandler().getAttributesToRequest();
    assertEquals(attrsToRequest.length, attrs.length);

    final HashSet<String> attrSet = new HashSet<String>(attrsToRequest.length);
    for (final String s : attrsToRequest)
    {
      attrSet.add(s.toLowerCase());
    }
    assertEquals(attrSet.size(), attrs.length);

    for (final String s : attrs)
    {
      assertTrue(attrSet.contains(s.toLowerCase()),
           "Persister for type " + p.getObjectHandler().getType().getName() +
                " will not request attribute " + s +
                ".  Attributes to request is " +
                Arrays.toString(attrsToRequest));
    }
  }
}
