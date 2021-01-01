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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;



/**
 * This class provides a set of test cases for the LDAModification class.
 */
public class ModificationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which takes a modification type and an
   * attribute name.
   *
   * @param  modificationType  The modification type to use for the test
   *                           modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testModificationTypes")
  public void testConstructor1(ModificationType modificationType)
         throws Exception
  {
    Modification mod = new Modification(modificationType, "cn");
    assertEquals(mod.getModificationType(), modificationType);
    assertEquals(mod.getAttribute(), new Attribute("cn"));
    assertEquals(mod.getAttributeName(), "cn");
    assertFalse(mod.hasValue());
    assertEquals(mod.getValues().length, 0);
    assertEquals(mod.getValueByteArrays().length, 0);

    ASN1Sequence modSequence = mod.encode();
    Modification decodedMod = Modification.decode(modSequence);
    assertEquals(decodedMod, mod);
    assertEquals(decodedMod.hashCode(), mod.hashCode());

    assertNotNull(mod.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    mod.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    mod.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the second constructor, which takes a modification type, an attribute
   * name, and a single string value.
   *
   * @param  modificationType  The modification type to use for the test
   *                           modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testModificationTypes")
  public void testConstructor2(ModificationType modificationType)
         throws Exception
  {
    Modification mod = new Modification(modificationType, "cn", "John Doe");
    assertEquals(mod.getModificationType(), modificationType);
    assertEquals(mod.getAttribute(), new Attribute("cn", "John Doe"));
    assertEquals(mod.getAttributeName(), "cn");
    assertTrue(mod.hasValue());
    assertEquals(mod.getValues().length, 1);
    assertEquals(mod.getValueByteArrays().length, 1);

    ASN1Sequence modSequence = mod.encode();
    Modification decodedMod = Modification.decode(modSequence);
    assertEquals(decodedMod, mod);
    assertEquals(decodedMod.hashCode(), mod.hashCode());

    assertNotNull(mod.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    mod.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    mod.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the third constructor, which takes a modification type, an attribute
   * name, and a single bye array value.
   *
   * @param  modificationType  The modification type to use for the test
   *                           modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testModificationTypes")
  public void testConstructor3(ModificationType modificationType)
         throws Exception
  {
    Modification mod = new Modification(modificationType, "cn",
                                        "John Doe".getBytes("UTF-8"));
    assertEquals(mod.getModificationType(), modificationType);
    assertEquals(mod.getAttribute(), new Attribute("cn", "John Doe"));
    assertEquals(mod.getAttributeName(), "cn");
    assertTrue(mod.hasValue());
    assertEquals(mod.getValues().length, 1);
    assertEquals(mod.getValueByteArrays().length, 1);

    ASN1Sequence modSequence = mod.encode();
    Modification decodedMod = Modification.decode(modSequence);
    assertEquals(decodedMod, mod);
    assertEquals(decodedMod.hashCode(), mod.hashCode());

    assertNotNull(mod.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    mod.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    mod.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fourth constructor, which takes a modification type, an attribute
   * name, and a set of string values, using varargs.
   *
   * @param  modificationType  The modification type to use for the test
   *                           modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testModificationTypes")
  public void testConstructor4Varargs(ModificationType modificationType)
         throws Exception
  {
    Modification mod = new Modification(modificationType, "cn", "John Doe",
                                        "Johnathan Doe");
    assertEquals(mod.getModificationType(), modificationType);
    assertEquals(mod.getAttribute(),
                 new Attribute("cn", "John Doe", "Johnathan Doe"));
    assertEquals(mod.getAttributeName(), "cn");
    assertTrue(mod.hasValue());
    assertEquals(mod.getValues().length, 2);
    assertEquals(mod.getValueByteArrays().length, 2);

    ASN1Sequence modSequence = mod.encode();
    Modification decodedMod = Modification.decode(modSequence);
    assertEquals(decodedMod, mod);
    assertEquals(decodedMod.hashCode(), mod.hashCode());

    assertNotNull(mod.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    mod.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    mod.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fourth constructor, which takes a modification type, an attribute
   * name, and a set of string values, using an array of strings.
   *
   * @param  modificationType  The modification type to use for the test
   *                           modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testModificationTypes")
  public void testConstructor4Array(ModificationType modificationType)
         throws Exception
  {
    String[] values =
    {
      "John Doe",
      "Johnathan Doe"
    };

    Modification mod = new Modification(modificationType, "cn", values);
    assertEquals(mod.getModificationType(), modificationType);
    assertEquals(mod.getAttribute(), new Attribute("cn", values));
    assertEquals(mod.getAttributeName(), "cn");
    assertTrue(mod.hasValue());
    assertEquals(mod.getValues().length, 2);
    assertEquals(mod.getValueByteArrays().length, 2);

    ASN1Sequence modSequence = mod.encode();
    Modification decodedMod = Modification.decode(modSequence);
    assertEquals(decodedMod, mod);
    assertEquals(decodedMod.hashCode(), mod.hashCode());

    assertNotNull(mod.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    mod.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    mod.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fifth constructor, which takes a modification type, an attribute
   * name, and a set of byte array values, using varargs.
   *
   * @param  modificationType  The modification type to use for the test
   *                           modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testModificationTypes")
  public void testConstructor5Varargs(ModificationType modificationType)
         throws Exception
  {
    Modification mod = new Modification(modificationType, "cn",
                                        "John Doe".getBytes("UTF-8"),
                                        "Johnathan Doe".getBytes("UTF-8"));
    assertEquals(mod.getModificationType(), modificationType);
    assertEquals(mod.getAttribute(),
                 new Attribute("cn", "John Doe", "Johnathan Doe"));
    assertEquals(mod.getAttributeName(), "cn");
    assertTrue(mod.hasValue());
    assertEquals(mod.getValues().length, 2);
    assertEquals(mod.getValueByteArrays().length, 2);

    ASN1Sequence modSequence = mod.encode();
    Modification decodedMod = Modification.decode(modSequence);
    assertEquals(decodedMod, mod);
    assertEquals(decodedMod.hashCode(), mod.hashCode());

    assertNotNull(mod.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    mod.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    mod.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the fourth constructor, which takes a modification type, an attribute
   * name, and a set of byte array values, using an array of byte arrays.
   *
   * @param  modificationType  The modification type to use for the test
   *                           modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testModificationTypes")
  public void testConstructor5Array(ModificationType modificationType)
         throws Exception
  {
    byte[][] values =
    {
      "John Doe".getBytes("UTF-8"),
      "Johnathan Doe".getBytes("UTF-8")
    };

    Modification mod = new Modification(modificationType, "cn", values);
    assertEquals(mod.getModificationType(), modificationType);
    assertEquals(mod.getAttribute(), new Attribute("cn", values));
    assertEquals(mod.getAttributeName(), "cn");
    assertTrue(mod.hasValue());
    assertEquals(mod.getValues().length, 2);
    assertEquals(mod.getValueByteArrays().length, 2);

    ASN1Sequence modSequence = mod.encode();
    Modification decodedMod = Modification.decode(modSequence);
    assertEquals(decodedMod, mod);
    assertEquals(decodedMod.hashCode(), mod.hashCode());

    assertNotNull(mod.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    mod.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    mod.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Tests the {@code equals} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEquals()
         throws Exception
  {
    Modification mod = new Modification(ModificationType.REPLACE, "cn");

    assertFalse(mod.equals(null));
    assertTrue(mod.equals(mod));
    assertFalse(mod.equals("foo"));
    assertTrue(mod.equals(new Modification(ModificationType.REPLACE, "cn")));
    assertFalse(mod.equals(new Modification(ModificationType.ADD, "cn")));
    assertFalse(mod.equals(new Modification(ModificationType.REPLACE, "sn")));
    assertFalse(mod.equals(new Modification(ModificationType.REPLACE, "cn",
                                            "John Doe")));
    assertFalse(mod.equals(new Modification(ModificationType.REPLACE, "cn",
                                            "John Doe", "Johnathan Doe")));

    mod = new Modification(ModificationType.REPLACE, "cn", "John Doe");
    assertFalse(mod.equals(new Modification(ModificationType.REPLACE, "cn")));
    assertTrue(mod.equals(new Modification(ModificationType.REPLACE, "cn",
                                           "John Doe")));
    assertFalse(mod.equals(new Modification(ModificationType.REPLACE, "cn",
                                            "John Doe", "Johnathan Doe")));

    mod = new Modification(ModificationType.REPLACE, "cn", "John Doe",
                           "Johnathan Doe");
    assertFalse(mod.equals(new Modification(ModificationType.REPLACE, "cn")));
    assertFalse(mod.equals(new Modification(ModificationType.REPLACE, "cn",
                                            "John Doe")));
    assertTrue(mod.equals(new Modification(ModificationType.REPLACE, "cn",
                                           "John Doe", "Johnathan Doe")));
    assertTrue(mod.equals(new Modification(ModificationType.REPLACE, "cn",
                                           "Johnathan Doe", "John Doe")));
    assertFalse(mod.equals(new Modification(ModificationType.REPLACE, "cn",
                                            "John Doe", "Johnny Doe")));
  }



  /**
   * Retrieves a set of modification types that can be used for testing
   * purposes.  Note that not all of the modification types can be used to
   * create technically valid modifications for all of the test cases as per the
   * protocol (e.g., the "add" type must always have one or more values, and the
   * "increment" type must always have exactly one integer value), but they are
   * sufficient for testing purposes and this SDK leaves it up to the server to
   * enforce these constraints.
   *
   * @return  A set of modification types that can be used for testing purposes.
   */
  @DataProvider(name = "testModificationTypes")
  public Object[][] getTestModificationTypes()
  {
    return new Object[][]
    {
      new Object[] { ModificationType.ADD },
      new Object[] { ModificationType.DELETE },
      new Object[] { ModificationType.REPLACE },
      new Object[] { ModificationType.INCREMENT },
      new Object[] { ModificationType.valueOf(4) },
    };
  }



  /**
   * Tests the {@code decode} method with a sequence containing an invalid
   * number of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidElementCount()
         throws Exception
  {
    Modification.decode(new ASN1Sequence(new ASN1Enumerated(0)));
  }



  /**
   * Tests the {@code decode} method with a sequence in which the first element
   * is not an enumerated.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeFirstElementNotEnumerated()
         throws Exception
  {
    Modification.decode(new ASN1Sequence(
         new ASN1OctetString(),
         new ASN1Sequence(
                  new ASN1OctetString("foo"))));
  }



  /**
   * Tests the {@code decode} method with a sequence in which the second element
   * is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSecondElementNotSequence()
         throws Exception
  {
    Modification.decode(new ASN1Sequence(
         new ASN1Enumerated(0),
         new ASN1Enumerated(0)));
  }



  /**
   * Tests the {@code decode} method with a sequence in which the value element
   * is not a set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidAttrElementCount()
         throws Exception
  {
    Modification.decode(new ASN1Sequence(
         new ASN1Enumerated(0),
         new ASN1Sequence(
                  new ASN1OctetString("foo"))));
  }



  /**
   * Tests the {@code decode} method with a sequence in which the value element
   * is not a set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValuesNotSet()
         throws Exception
  {
    Modification.decode(new ASN1Sequence(
         new ASN1Enumerated(0),
         new ASN1Sequence(
                  new ASN1OctetString("foo"),
                  new ASN1Enumerated(0))));
  }



  /**
   * Tests the behavior of the toCode method for a sensitive attribute.
   *
   * @param  modificationType  The modification type to use for the test
   *                           modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testModificationTypes")
  public void testToCodeWithSensitiveAttribute(
                   final ModificationType modificationType)
         throws Exception
  {
    Modification mod = new Modification(modificationType, "userPassword",
         "sensitive");
    assertEquals(mod.getModificationType(), modificationType);
    assertEquals(mod.getAttribute(),
         new Attribute("userPassword", "sensitive"));
    assertEquals(mod.getAttributeName(), "userPassword");
    assertTrue(mod.hasValue());
    assertEquals(mod.getValues().length, 1);
    assertEquals(mod.getValueByteArrays().length, 1);

    ASN1Sequence modSequence = mod.encode();
    Modification decodedMod = Modification.decode(modSequence);
    assertEquals(decodedMod, mod);
    assertEquals(decodedMod.hashCode(), mod.hashCode());

    assertNotNull(mod.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    mod.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    mod.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides coverage for the toString method with ASCII and non-ASCII values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToString()
         throws Exception
  {
    final Modification asciiMod = new Modification(ModificationType.REPLACE,
         "value 1",
         "value 2",
         "value 3");
    final String asciiToString = asciiMod.toString();
    assertTrue(asciiToString.contains(", values="));
    assertFalse(asciiToString.contains(", base64Values="));

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    asciiMod.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    asciiMod.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());

    final Modification nonASCIIMod = new Modification(ModificationType.REPLACE,
         "v\u00E0l\u00FC\u00E9 1",
         "v\u00E0l\u00FC\u00E9 2",
         "v\u00E0l\u00FC\u00E9 3");
    final String nonASCIIToString = nonASCIIMod.toString();
    assertFalse(nonASCIIToString.contains(", values="));
    assertTrue(nonASCIIToString.contains(", base64Values="));

    toCodeLines.clear();
    nonASCIIMod.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    nonASCIIMod.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());

    final Modification mixedMod = new Modification(ModificationType.REPLACE,
         "value 1",
         "v\u00E0l\u00FC\u00E9 2",
         "v\u00E0l\u00FC\u00E9 3");
    final String mixedToString = mixedMod.toString();
    assertFalse(mixedToString.contains(", values="));
    assertTrue(mixedToString.contains(", base64Values="));

    toCodeLines.clear();
    mixedMod.toCode(toCodeLines, 0, null, null);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    mixedMod.toCode(toCodeLines, 4, "FirstLinePrefix-", "-LastLineSuffix");
    assertFalse(toCodeLines.isEmpty());
  }
}
