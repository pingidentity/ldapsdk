/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.util.ArrayList;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the ModifyRequest class.
 */
public class ModifyRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which takes a string DN and a single
   * modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    ModifyRequest modifyRequest =
         new ModifyRequest("dc=example,dc=com",
                  new Modification(ModificationType.REPLACE, "description",
                                   "foo"));
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 1);

    assertFalse(modifyRequest.hasControl());
    assertFalse(modifyRequest.hasControl("1.2.3.4"));
    assertNull(modifyRequest.getControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 0);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);

    assertEquals(modifyRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST);

    assertNull(modifyRequest.getIntermediateResponseListener());
    modifyRequest.setIntermediateResponseListener(
         new TestIntermediateResponseListener());
    assertNotNull(modifyRequest.getIntermediateResponseListener());
    modifyRequest.setIntermediateResponseListener(null);
    assertNull(modifyRequest.getIntermediateResponseListener());
  }



  /**
   * Tests the first constructor, which takes a string DN and a single
   * modification, using {@code null} elements.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1Null()
  {
    new ModifyRequest((String) null, (Modification) null);
  }



  /**
   * Tests the second constructor, which takes a string DN and an array of
   * modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    Modification[] mods =
    {
      new Modification(ModificationType.REPLACE, "description", "foo"),
      new Modification(ModificationType.ADD, "cn", "bar"),
      new Modification(ModificationType.DELETE, "displayName", "baz")
    };

    ModifyRequest modifyRequest = new ModifyRequest("dc=example,dc=com",  mods);
    modifyRequest.setFollowReferrals(true);
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 3);

    assertFalse(modifyRequest.hasControl());
    assertFalse(modifyRequest.hasControl("1.2.3.4"));
    assertNull(modifyRequest.getControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 0);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);
  }



  /**
   * Tests the second constructor, which takes a string DN and an array of
   * modifications, using {@code null} elements.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2Null()
  {
    new ModifyRequest((String) null, (Modification[]) null);
  }



  /**
   * Tests the third constructor, which takes a string DN and a list of
   * modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    ArrayList<Modification> mods = new ArrayList<Modification>(3);
    mods.add(new Modification(ModificationType.REPLACE, "description", "foo"));
    mods.add(new Modification(ModificationType.ADD, "cn", "bar"));
    mods.add(new Modification(ModificationType.DELETE, "displayName", "baz"));
    mods.add(new Modification(ModificationType.INCREMENT, "baz", "1"));

    ModifyRequest modifyRequest = new ModifyRequest("dc=example,dc=com",  mods);
    modifyRequest.setFollowReferrals(false);
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 4);

    assertFalse(modifyRequest.hasControl());
    assertFalse(modifyRequest.hasControl("1.2.3.4"));
    assertNull(modifyRequest.getControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 0);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);
  }



  /**
   * Tests the third constructor, which takes a string DN and a list of
   * modifications, using {@code null} elements.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3Null()
  {
    new ModifyRequest((String) null, (ArrayList<Modification>) null);
  }



  /**
   * Tests the fourth constructor, which takes a DN object and a single
   * modification.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    ModifyRequest modifyRequest =
         new ModifyRequest(new DN("dc=example,dc=com"),
                  new Modification(ModificationType.REPLACE, "description",
                                   "foo"));
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 1);

    assertFalse(modifyRequest.hasControl());
    assertFalse(modifyRequest.hasControl("1.2.3.4"));
    assertNull(modifyRequest.getControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 0);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);
  }



  /**
   * Tests the fourth constructor, which takes a string DN and a single
   * modification, using {@code null} elements.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4Null()
  {
    new ModifyRequest((DN) null, (Modification) null);
  }



  /**
   * Tests the fifth constructor, which takes a DN object and an array of
   * modifications.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5()
         throws Exception
  {
    Modification[] mods =
    {
      new Modification(ModificationType.REPLACE, "description", "foo"),
      new Modification(ModificationType.ADD, "cn", "bar"),
      new Modification(ModificationType.DELETE, "displayName", "baz")
    };

    ModifyRequest modifyRequest =
         new ModifyRequest(new DN("dc=example,dc=com"),  mods);
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 3);

    assertFalse(modifyRequest.hasControl());
    assertFalse(modifyRequest.hasControl("1.2.3.4"));
    assertNull(modifyRequest.getControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 0);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);
  }



  /**
   * Tests the fifth constructor, which takes a DN object and an array of
   * modifications, using {@code null} elements.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor5Null()
  {
    new ModifyRequest((DN) null, (Modification[]) null);
  }



  /**
   * Tests the sixth constructor, which takes a DN object and a list of
   * modifications.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6()
         throws Exception
  {
    ArrayList<Modification> mods = new ArrayList<Modification>(3);
    mods.add(new Modification(ModificationType.REPLACE, "description", "foo"));
    mods.add(new Modification(ModificationType.ADD, "cn", "bar"));
    mods.add(new Modification(ModificationType.DELETE, "displayName", "baz"));

    ModifyRequest modifyRequest =
         new ModifyRequest(new DN("dc=example,dc=com"),  mods);
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 3);

    assertFalse(modifyRequest.hasControl());
    assertFalse(modifyRequest.hasControl("1.2.3.4"));
    assertNull(modifyRequest.getControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 0);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);
  }



  /**
   * Tests the sixth constructor, which takes a DN object and a list of
   * modifications, using {@code null} elements.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor6Null()
  {
    new ModifyRequest((DN) null, (ArrayList<Modification>) null);
  }



  /**
   * Tests the seventh constructor, which takes a string DN, a single
   * modification, and a set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ModifyRequest modifyRequest =
         new ModifyRequest("dc=example,dc=com",
                  new Modification(ModificationType.REPLACE, "description",
                                   "foo"),
                  controls);
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 1);

    assertTrue(modifyRequest.hasControl());
    assertTrue(modifyRequest.hasControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControl("1.2.3.4"));
    assertFalse(modifyRequest.hasControl("1.2.3.6"));
    assertNull(modifyRequest.getControl("1.2.3.6"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 2);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);
  }



  /**
   * Tests the eighth constructor, which takes a string DN, an array of
   * modifications, and a set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    Modification[] mods =
    {
      new Modification(ModificationType.REPLACE, "description", "foo"),
      new Modification(ModificationType.ADD, "cn", "bar"),
      new Modification(ModificationType.DELETE, "displayName", "baz")
    };

    ModifyRequest modifyRequest =
         new ModifyRequest("dc=example,dc=com",  mods, controls);
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 3);

    assertTrue(modifyRequest.hasControl());
    assertTrue(modifyRequest.hasControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControl("1.2.3.4"));
    assertFalse(modifyRequest.hasControl("1.2.3.6"));
    assertNull(modifyRequest.getControl("1.2.3.6"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 2);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);
  }



  /**
   * Tests the ninth constructor, which takes a string DN and a list of
   * modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor9()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ArrayList<Modification> mods = new ArrayList<Modification>(3);
    mods.add(new Modification(ModificationType.REPLACE, "description", "foo"));
    mods.add(new Modification(ModificationType.ADD, "cn", "bar"));
    mods.add(new Modification(ModificationType.DELETE, "displayName", "baz"));

    ModifyRequest modifyRequest =
         new ModifyRequest("dc=example,dc=com",  mods, controls);
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 3);

    assertTrue(modifyRequest.hasControl());
    assertTrue(modifyRequest.hasControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControl("1.2.3.4"));
    assertFalse(modifyRequest.hasControl("1.2.3.6"));
    assertNull(modifyRequest.getControl("1.2.3.6"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 2);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);
  }



  /**
   * Tests the tenth constructor, which takes a DN object and a single
   * modification.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor10()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ModifyRequest modifyRequest =
         new ModifyRequest(new DN("dc=example,dc=com"),
                  new Modification(ModificationType.REPLACE, "description",
                                   "foo"),
                  controls);
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 1);

    assertTrue(modifyRequest.hasControl());
    assertTrue(modifyRequest.hasControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControl("1.2.3.4"));
    assertFalse(modifyRequest.hasControl("1.2.3.6"));
    assertNull(modifyRequest.getControl("1.2.3.6"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 2);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);
  }



  /**
   * Tests the eleventh constructor, which takes a DN object and an array of
   * modifications.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor11()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    Modification[] mods =
    {
      new Modification(ModificationType.REPLACE, "description", "foo"),
      new Modification(ModificationType.ADD, "cn", "bar"),
      new Modification(ModificationType.DELETE, "displayName", "baz")
    };

    ModifyRequest modifyRequest =
         new ModifyRequest(new DN("dc=example,dc=com"),  mods, controls);
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 3);

    assertTrue(modifyRequest.hasControl());
    assertTrue(modifyRequest.hasControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControl("1.2.3.4"));
    assertFalse(modifyRequest.hasControl("1.2.3.6"));
    assertNull(modifyRequest.getControl("1.2.3.6"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 2);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);
  }



  /**
   * Tests the twelfth constructor, which takes a DN object and a list of
   * modifications.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor12()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ArrayList<Modification> mods = new ArrayList<Modification>(3);
    mods.add(new Modification(ModificationType.REPLACE, "description", "foo"));
    mods.add(new Modification(ModificationType.ADD, "cn", "bar"));
    mods.add(new Modification(ModificationType.DELETE, "displayName", "baz"));

    ModifyRequest modifyRequest =
         new ModifyRequest(new DN("dc=example,dc=com"),  mods, controls);
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 3);

    assertTrue(modifyRequest.hasControl());
    assertTrue(modifyRequest.hasControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControl("1.2.3.4"));
    assertFalse(modifyRequest.hasControl("1.2.3.6"));
    assertNull(modifyRequest.getControl("1.2.3.6"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 2);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);
  }



  /**
   * Tests the thirteenth constructor, which takes a string representation of an
   * LDIF modify change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor13()
         throws Exception
  {
    ModifyRequest modifyRequest =
         new ModifyRequest("dn: dc=example,dc=com",
                           "changetype: modify",
                           "replace: description",
                           "description: foo",
                           "-",
                           "add: cn",
                           "cn: bar",
                           "-",
                           "delete: displayName",
                           "displayName: baz");
    modifyRequest = modifyRequest.duplicate();

    assertNotNull(modifyRequest.getDN());
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertNotNull(modifyRequest.getModifications());
    assertEquals(modifyRequest.getModifications().size(), 3);

    assertFalse(modifyRequest.hasControl());
    assertFalse(modifyRequest.hasControl("1.2.3.4"));
    assertNull(modifyRequest.getControl("1.2.3.4"));
    assertNotNull(modifyRequest.getControls());
    assertEquals(modifyRequest.getControls().length, 0);

    assertNotNull(modifyRequest.toLDIFChangeRecord());

    assertNotNull(modifyRequest.toLDIF());
    assertTrue(modifyRequest.toLDIF().length > 0);

    assertNotNull(modifyRequest.toLDIFString());

    assertNotNull(modifyRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyRequest);
  }



  /**
   * Tests the thirteenth constructor with a set of strings that do not
   * represent a valid change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testConstructor13InvalidChangeRecord()
         throws Exception
  {
    new ModifyRequest("invalid line 1",
                      "invalid line 2");
  }



  /**
   * Tests the thirteenth constructor with a set of strings that represent a
   * valid change record, but not a modify change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testConstructor13NotModifyChangeRecord()
         throws Exception
  {
    new ModifyRequest("dn: dc=example,dc=com",
                      "changetype: delete");
  }



  /**
   * Tests the {@code getDN} and {@code setDN} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetDN()
         throws Exception
  {
    ModifyRequest modifyRequest =
         new ModifyRequest("dc=example,dc=com",
                  new Modification(ModificationType.REPLACE, "description",
                                   "foo"));
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    modifyRequest.setDN("o=example.com");
    assertEquals(modifyRequest.getDN(), "o=example.com");

    modifyRequest.setDN(new DN("o=example.net"));
    assertEquals(modifyRequest.getDN(), "o=example.net");

    testEncoding(modifyRequest);
  }



  /**
   * Tests the methods used to manipulate the set of modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetModifications()
         throws Exception
  {
    ModifyRequest modifyRequest =
         new ModifyRequest("dc=example,dc=com",
                  new Modification(ModificationType.REPLACE, "description",
                                   "foo"));
    assertEquals(modifyRequest.getModifications().size(), 1);

    modifyRequest.addModification(new Modification(ModificationType.ADD, "cn",
                                                   "bar"));
    assertEquals(modifyRequest.getModifications().size(), 2);

    assertTrue(modifyRequest.removeModification(
         new Modification(ModificationType.REPLACE, "description", "foo")));
    assertEquals(modifyRequest.getModifications().size(), 1);

    assertFalse(modifyRequest.removeModification(
         new Modification(ModificationType.REPLACE, "description", "foo")));
    assertEquals(modifyRequest.getModifications().size(), 1);

    Modification[] mods =
    {
      new Modification(ModificationType.REPLACE, "description", "foo"),
      new Modification(ModificationType.ADD, "cn", "bar"),
      new Modification(ModificationType.DELETE, "displayName", "baz")
    };
    modifyRequest.setModifications(mods);
    assertEquals(modifyRequest.getModifications().size(), 3);

    modifyRequest.setModifications(
         new Modification(ModificationType.REPLACE, "description", "foo"));
    assertEquals(modifyRequest.getModifications().size(), 1);

    ArrayList<Modification> modList = new ArrayList<Modification>(2);
    modList.add(new Modification(ModificationType.REPLACE, "description",
                                 "foo"));
    modList.add(new Modification(ModificationType.ADD, "cn", "bar"));
    modifyRequest.setModifications(modList);
    assertEquals(modifyRequest.getModifications().size(), 2);

    testEncoding(modifyRequest);
  }



  /**
   * Tests to ensure that the encoding for the provided modify request is
   * identical when using the stream-based and non-stream-based ASN.1 encoding
   * mechanisms.
   *
   * @param  modifyRequest  The modify request to be tested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void testEncoding(final ModifyRequest modifyRequest)
          throws Exception
  {
    ASN1Element protocolOpElement = modifyRequest.encodeProtocolOp();

    ASN1Buffer b = new ASN1Buffer();
    modifyRequest.writeTo(b);

    assertTrue(Arrays.equals(b.toByteArray(), protocolOpElement.encode()));
  }
}
