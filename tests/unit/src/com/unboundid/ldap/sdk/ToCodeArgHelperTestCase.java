/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the {@code ToCodeArgHelper}
 * class.
 */
public final class ToCodeArgHelperTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the createByte method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateByte()
         throws Exception
  {
    // A simple non-printable byte without any comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createByte((byte) 0x00, false);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "0x00");

    assertNull(helper.getComment());


    // A simple printable byte with a comment.
    helper = ToCodeArgHelper.createByte((byte) 0x41, true);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "0x41");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "\"A\"");


    // A simple non-printable byte with a comment.
    helper = ToCodeArgHelper.createByte((byte) 0x80, true);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(byte) 0x80");

    assertNull(helper.getComment());


    // A simple non-printable byte with a comment.
    helper = ToCodeArgHelper.createByte((byte) 0xFF, true);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(byte) 0xff");

    assertNull(helper.getComment());
  }



  /**
   * Provides test coverage for the createByteArray method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateByteArray()
         throws Exception
  {
    // A null array without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createByteArray(null, false, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(byte[]) null");

    assertNull(helper.getComment());


    // A null array with a comment.
    helper = ToCodeArgHelper.createByteArray(null, true, "Byte comment");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(byte[]) null");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Byte comment");


    // An empty array without a comment.
    helper = ToCodeArgHelper.createByteArray(StaticUtils.NO_BYTES, false, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "new byte[0]");

    assertNull(helper.getComment());


    // A null array with a comment.
    helper = ToCodeArgHelper.createByteArray(StaticUtils.NO_BYTES, true,
         "Byte array comment");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "new byte[0]");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Byte array comment");


    // A non-empty array without a comment.
    final byte[] testArray =
    {
      (byte) 0x00,
      (byte) 0x48, // H
      (byte) 0x69, // i
      (byte) 0x80,
      (byte) 0xFF
    };
    helper = ToCodeArgHelper.createByteArray(testArray, false, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines(),
         Arrays.asList(
              "new byte[]",
              "{",
              "  0x00,",
              "  0x48,",
              "  0x69,",
              "  (byte) 0x80,",
              "  (byte) 0xff",
              "}"));

    assertNull(helper.getComment());


    // A non-empty array with a comment.
    helper = ToCodeArgHelper.createByteArray(testArray, true,
         "Byte array comment");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines(),
         Arrays.asList(
              "new byte[]",
              "{",
              "  0x00,",
              "  0x48, // \"H\"",
              "  0x69, // \"i\"",
              "  (byte) 0x80,",
              "  (byte) 0xff",
              "}"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Byte array comment");
  }



  /**
   * Provides test coverage for the createBoolean method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateBoolean()
         throws Exception
  {
    // A true value without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createBoolean(true, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "true");

    assertNull(helper.getComment());


    // A true value with a comment.
    helper = ToCodeArgHelper.createBoolean(true, "True dat");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "true");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "True dat");


    // A false value without a comment.
    helper = ToCodeArgHelper.createBoolean(false, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "false");

    assertNull(helper.getComment());


    // A false value with a comment.
    helper = ToCodeArgHelper.createBoolean(false, "No way");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "false");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "No way");
  }



  /**
   * Provides test coverage for the createInteger method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateInteger()
         throws Exception
  {
    // A zero value without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createInteger(0, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "0");

    assertNull(helper.getComment());


    // A negative value with a comment.
    helper = ToCodeArgHelper.createInteger(-1234, "Negative");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "-1234");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Negative");


    // A positive value without a comment.
    helper = ToCodeArgHelper.createInteger(123456, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "123456");

    assertNull(helper.getComment());


    // A positive long value with a comment.
    helper = ToCodeArgHelper.createInteger(12345678910L, "Long");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "12345678910L");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Long");
  }



  /**
   * Provides test coverage for the createString method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateString()
         throws Exception
  {
    // A null value without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createString(null, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(String) null");

    assertNull(helper.getComment());


    // A null value with a comment.
    helper = ToCodeArgHelper.createString(null, "Null string");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(String) null");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Null string");


    // An empty string without a comment.
    helper = ToCodeArgHelper.createString("", null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "\"\"");

    assertNull(helper.getComment());


    // An empty string with a comment.
    helper = ToCodeArgHelper.createString("", "Empty");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "\"\"");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Empty");


    // A non-empty string without a comment.
    helper = ToCodeArgHelper.createString("abcd", null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "\"abcd\"");

    assertNull(helper.getComment());


    // A non-empty string with a comment.
    helper = ToCodeArgHelper.createString("\"Hello, Jalape\\c3\\b1o\"",
         "Non-ASCII");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0),
         "\"\\\"Hello, Jalape\\c3\\b1o\\\"\"");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Non-ASCII");
  }



  /**
   * Provides test coverage for the createASN1OctetString method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateASN1OctetString()
         throws Exception
  {
    // A null value without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createASN1OctetString(null, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(ASN1OctetString) null");

    assertNull(helper.getComment());


    // A null value with a comment.
    helper = ToCodeArgHelper.createASN1OctetString(null, "Null octet string");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(ASN1OctetString) null");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Null octet string");


    // An empty octet string with the universal type and no comment.
    helper = ToCodeArgHelper.createASN1OctetString(new ASN1OctetString(), null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "new ASN1OctetString()");

    assertNull(helper.getComment());


    // An empty octet string with a custom type and a comment.
    helper = ToCodeArgHelper.createASN1OctetString(
         new ASN1OctetString((byte) 0x80, ""), "Custom empty octet string");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertEquals(helper.getLines(),
         Arrays.asList(
              "new ASN1OctetString(",
              "     (byte) 0x80)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Custom empty octet string");


    // An octet string with the universal type, a printable string value, and no
    // comment.
    helper = ToCodeArgHelper.createASN1OctetString(
         new ASN1OctetString("printable"), null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertEquals(helper.getLines(),
         Arrays.asList(
              "new ASN1OctetString(",
              "     \"printable\")"));

    assertNull(helper.getComment());


    // An octet string with a custom type, a non-printable value, and a comment.
    final byte[] testArray =
    {
      (byte) 0x00,
      (byte) 0x48, // H
      (byte) 0x69, // i
      (byte) 0x80,
      (byte) 0xFF
    };
    helper = ToCodeArgHelper.createASN1OctetString(
         new ASN1OctetString((byte) 0x8F, testArray), "How's this?");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertEquals(helper.getLines(),
         Arrays.asList(
              "new ASN1OctetString(",
              "     (byte) 0x8f,",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "How's this?");
  }



  /**
   * Provides test coverage for the createModificationType method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateModificationType()
         throws Exception
  {
    // A null value without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createModificationType(null, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(ModificationType) null");

    assertNull(helper.getComment());


    // A null value with a comment.
    helper = ToCodeArgHelper.createModificationType(null,
         "Null modification type");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(ModificationType) null");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Null modification type");


    // All defined modification type values with and without comments.
    for (final ModificationType t : ModificationType.values())
    {
      helper = ToCodeArgHelper.createModificationType(t, null);
      assertNotNull(helper);

      assertNotNull(helper.getLines());
      assertFalse(helper.getLines().isEmpty());
      assertEquals(helper.getLines().size(), 1);
      assertEquals(helper.getLines().get(0), "ModificationType." + t.getName());

      assertNull(helper.getComment());


      helper = ToCodeArgHelper.createModificationType(t, "Defined type");
      assertNotNull(helper);

      assertNotNull(helper.getLines());
      assertFalse(helper.getLines().isEmpty());
      assertEquals(helper.getLines().size(), 1);
      assertEquals(helper.getLines().get(0), "ModificationType." + t.getName());

      assertNotNull(helper.getComment());
      assertEquals(helper.getComment(), "Defined type");
    }


    // An undefined modification type without a comment.
    helper = ToCodeArgHelper.createModificationType(
         ModificationType.valueOf(1234), null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "ModificationType.valueOf(1234)");

    assertNull(helper.getComment());


    // An undefined modification type with a comment.
    helper = ToCodeArgHelper.createModificationType(
         ModificationType.valueOf(5678), "Unexpected value");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "ModificationType.valueOf(5678)");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Unexpected value");
  }



  /**
   * Provides test coverage for the createScope method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateScope()
         throws Exception
  {
    // A null value without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createScope(null, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(SearchScope) null");

    assertNull(helper.getComment());


    // A null value with a comment.
    helper = ToCodeArgHelper.createScope(null, "Null scope");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(SearchScope) null");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Null scope");


    // All defined modification type values with and without comments.
    for (final SearchScope s : SearchScope.values())
    {
      helper = ToCodeArgHelper.createScope(s, null);
      assertNotNull(helper);

      assertNotNull(helper.getLines());
      assertFalse(helper.getLines().isEmpty());
      assertEquals(helper.getLines().size(), 1);
      assertEquals(helper.getLines().get(0), "SearchScope." + s.getName());

      assertNull(helper.getComment());


      helper = ToCodeArgHelper.createScope(s, "Defined scope");
      assertNotNull(helper);

      assertNotNull(helper.getLines());
      assertFalse(helper.getLines().isEmpty());
      assertEquals(helper.getLines().size(), 1);
      assertEquals(helper.getLines().get(0), "SearchScope." + s.getName());

      assertNotNull(helper.getComment());
      assertEquals(helper.getComment(), "Defined scope");
    }


    // An undefined modification type without a comment.
    helper = ToCodeArgHelper.createScope(SearchScope.valueOf(1234), null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "SearchScope.valueOf(1234)");

    assertNull(helper.getComment());


    // An undefined modification type with a comment.
    helper = ToCodeArgHelper.createScope(SearchScope.valueOf(5678),
         "Unexpected value");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "SearchScope.valueOf(5678)");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Unexpected value");
  }



  /**
   * Provides test coverage for the createDerefPolicy method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateDerefPolicy()
         throws Exception
  {
    // A null value without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createDerefPolicy(null, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(DereferencePolicy) null");

    assertNull(helper.getComment());


    // A null value with a comment.
    helper = ToCodeArgHelper.createDerefPolicy(null, "Null policy");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(DereferencePolicy) null");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Null policy");


    // All defined modification type values with and without comments.
    for (final DereferencePolicy s : DereferencePolicy.values())
    {
      helper = ToCodeArgHelper.createDerefPolicy(s, null);
      assertNotNull(helper);

      assertNotNull(helper.getLines());
      assertFalse(helper.getLines().isEmpty());
      assertEquals(helper.getLines().size(), 1);
      assertEquals(helper.getLines().get(0),
           "DereferencePolicy." + s.getName());

      assertNull(helper.getComment());


      helper = ToCodeArgHelper.createDerefPolicy(s, "Defined policy");
      assertNotNull(helper);

      assertNotNull(helper.getLines());
      assertFalse(helper.getLines().isEmpty());
      assertEquals(helper.getLines().size(), 1);
      assertEquals(helper.getLines().get(0),
           "DereferencePolicy." + s.getName());

      assertNotNull(helper.getComment());
      assertEquals(helper.getComment(), "Defined policy");
    }


    // An undefined modification type without a comment.
    helper = ToCodeArgHelper.createDerefPolicy(DereferencePolicy.valueOf(1234),
         null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "DereferencePolicy.valueOf(1234)");

    assertNull(helper.getComment());


    // An undefined modification type with a comment.
    helper = ToCodeArgHelper.createDerefPolicy(DereferencePolicy.valueOf(5678),
         "Unexpected value");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "DereferencePolicy.valueOf(5678)");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Unexpected value");
  }



  /**
   * Provides test coverage for the createAttribute method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAttribute()
         throws Exception
  {
    // A null value without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createAttribute(null, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(Attribute) null");

    assertNull(helper.getComment());


    // A null value with a comment.
    helper = ToCodeArgHelper.createAttribute(null, "Null attribute");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(Attribute) null");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Null attribute");


    // An attribute without any values.
    helper = ToCodeArgHelper.createAttribute(new Attribute("givenName"),
         "Empty attribute");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "new Attribute(\"givenName\")");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Empty attribute");


    // An attribute with a single value that is a printable string
    helper = ToCodeArgHelper.createAttribute(new Attribute("givenName", "John"),
         "Single string value");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Attribute(",
              "     \"givenName\",",
              "     \"John\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Single string value");


    // An attribute with a single value that is not a printable string
    final byte[] testValueBytes =
    {
      (byte) 0x00,
      (byte) 0x48, // H
      (byte) 0x69, // i
      (byte) 0x80,
      (byte) 0xFF
    };
    helper = ToCodeArgHelper.createAttribute(
         new Attribute("givenName", testValueBytes),
         "Single binary value");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Attribute(",
              "     \"givenName\",",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Single binary value");


    // A sensitive attribute with a single value
    helper = ToCodeArgHelper.createAttribute(
         new Attribute("userPassword", "password"),
         "Single redacted value");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Attribute(",
              "     \"userPassword\",",
              "     \"---redacted-value---\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Single redacted value");


    // An attribute with multiple values that are all printable strings
    helper = ToCodeArgHelper.createAttribute(
         new Attribute("givenName", "Johnathan", "John", "Johnny"),
         "Multiple string values");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Attribute(",
              "     \"givenName\",",
              "     \"Johnathan\",",
              "     \"John\",",
              "     \"Johnny\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Multiple string values");


    // An attribute with multiple values, in which not all of them are printable
    // strings.
    helper = ToCodeArgHelper.createAttribute(
         new Attribute("givenName", "John".getBytes("UTF-8"), testValueBytes),
         "Multiple binary values");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Attribute(",
              "     \"givenName\",",
              "     new byte[]",
              "     {",
              "       0x4a, // \"J\"",
              "       0x6f, // \"o\"",
              "       0x68, // \"h\"",
              "       0x6e // \"n\"",
              "     },",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Multiple binary values");


    // A sensitive attribute with multiple values.
    helper = ToCodeArgHelper.createAttribute(
         new Attribute("userPassword", "password", "anotherPassword"),
         "Multiple redacted values");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Attribute(",
              "     \"userPassword\",",
              "     \"---redacted-value-1---\",",
              "     \"---redacted-value-2---\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Multiple redacted values");
  }



  /**
   * Provides test coverage for the createModification method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateModification()
         throws Exception
  {
    // A null value without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createModification(null, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(Modification) null");

    assertNull(helper.getComment());


    // A null value with a comment.
    helper = ToCodeArgHelper.createModification(null, "Null mod");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(Modification) null");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Null mod");


    // A modification without any values.
    helper = ToCodeArgHelper.createModification(
         new Modification(ModificationType.REPLACE, "description"),
         "No values");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Modification(",
              "     ModificationType.REPLACE,",
              "     \"description\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "No values");


    // A modification with a single printable string value.
    helper = ToCodeArgHelper.createModification(
         new Modification(ModificationType.ADD, "description", "foo"),
         "Single printable value");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Modification(",
              "     ModificationType.ADD,",
              "     \"description\",",
              "     \"foo\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Single printable value");


    // A modification with a single non-printable value.
    final byte[] testArray =
    {
      (byte) 0x00,
      (byte) 0x48, // H
      (byte) 0x69, // i
      (byte) 0x80,
      (byte) 0xFF
    };
    helper = ToCodeArgHelper.createModification(
         new Modification(ModificationType.DELETE, "description", testArray),
         "Single non-printable value");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Modification(",
              "     ModificationType.DELETE,",
              "     \"description\",",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Single non-printable value");


    // A modification with a single redacted value.
    helper = ToCodeArgHelper.createModification(
         new Modification(ModificationType.REPLACE, "userPassword", "password"),
         "Single redacted value");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Modification(",
              "     ModificationType.REPLACE,",
              "     \"userPassword\",",
              "     \"---redacted-value---\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Single redacted value");


    // A modification with a multiple printable string value s.
    helper = ToCodeArgHelper.createModification(
         new Modification(ModificationType.ADD, "description", "foo", "bar"),
         "Multiple printable values");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Modification(",
              "     ModificationType.ADD,",
              "     \"description\",",
              "     \"foo\",",
              "     \"bar\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Multiple printable values");


    // A modification with multiple values in which not all are printable.
    helper = ToCodeArgHelper.createModification(
         new Modification(ModificationType.REPLACE, "description",
              "John".getBytes("UTF-8"), testArray),
         "Multiple non-printable values");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Modification(",
              "     ModificationType.REPLACE,",
              "     \"description\",",
              "     new byte[]",
              "     {",
              "       0x4a, // \"J\"",
              "       0x6f, // \"o\"",
              "       0x68, // \"h\"",
              "       0x6e // \"n\"",
              "     },",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Multiple non-printable values");


    // A modification with a multiple redacted values.
    helper = ToCodeArgHelper.createModification(
         new Modification(ModificationType.REPLACE, "userPassword",
              "password1", "passwordTwo"),
         "Multiple redacted values");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Modification(",
              "     ModificationType.REPLACE,",
              "     \"userPassword\",",
              "     \"---redacted-value-1---\",",
              "     \"---redacted-value-2---\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Multiple redacted values");
  }



  /**
   * Provides test coverage for the createFilter method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFilter()
         throws Exception
  {
    // A null value without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createFilter(null, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(Filter) null");

    assertNull(helper.getComment());


    // A null value with a comment.
    helper = ToCodeArgHelper.createFilter(null, "Null filter");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(Filter) null");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Null filter");


    // A presence filter.
    helper = ToCodeArgHelper.createFilter(
         Filter.createPresenceFilter("description"), "Presence");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createPresenceFilter(",
              "     \"description\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Presence");


    // An equality filter with a printable value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createEqualityFilter("description", "foo"),
         "Printable equality");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createEqualityFilter(",
              "     \"description\",",
              "     \"foo\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Printable equality");


    // An equality filter with a non-printable value.
    final byte[] testArray =
    {
      (byte) 0x00,
      (byte) 0x48, // H
      (byte) 0x69, // i
      (byte) 0x80,
      (byte) 0xFF
    };
    helper = ToCodeArgHelper.createFilter(
         Filter.createEqualityFilter("description", testArray),
         "Non-printable equality");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createEqualityFilter(",
              "     \"description\",",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Non-printable equality");


    // An equality filter with a redacted value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createEqualityFilter("userPassword", "password"),
         "Redacted equality");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createEqualityFilter(",
              "     \"userPassword\",",
              "     \"---redacted-value---\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Redacted equality");


    // A greater-or-equal filter with a printable value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createGreaterOrEqualFilter("description", "foo"),
         "Printable greater-or-equal");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createGreaterOrEqualFilter(",
              "     \"description\",",
              "     \"foo\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Printable greater-or-equal");


    // A greater-or-equal filter with a non-printable value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createGreaterOrEqualFilter("description", testArray),
         "Non-printable greater-or-equal");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createGreaterOrEqualFilter(",
              "     \"description\",",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Non-printable greater-or-equal");


    // A greater-or-equal filter with a redacted value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createGreaterOrEqualFilter("userPassword", "password"),
         "Redacted greater-or-equal");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createGreaterOrEqualFilter(",
              "     \"userPassword\",",
              "     \"---redacted-value---\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Redacted greater-or-equal");


    // A less-or-equal filter with a printable value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createLessOrEqualFilter("description", "foo"),
         "Printable less-or-equal");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createLessOrEqualFilter(",
              "     \"description\",",
              "     \"foo\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Printable less-or-equal");


    // A less-or-equal filter with a non-printable value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createLessOrEqualFilter("description", testArray),
         "Non-printable less-or-equal");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createLessOrEqualFilter(",
              "     \"description\",",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Non-printable less-or-equal");


    // A less-or-equal filter with a redacted value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createLessOrEqualFilter("userPassword", "password"),
         "Redacted less-or-equal");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createLessOrEqualFilter(",
              "     \"userPassword\",",
              "     \"---redacted-value---\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Redacted less-or-equal");


    // An approximate match filter with a printable value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createApproximateMatchFilter("description", "foo"),
         "Printable approximate");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createApproximateMatchFilter(",
              "     \"description\",",
              "     \"foo\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Printable approximate");


    // An approximate match filter with a non-printable value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createApproximateMatchFilter("description", testArray),
         "Non-printable approximate");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createApproximateMatchFilter(",
              "     \"description\",",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Non-printable approximate");


    // An approximate match filter with a redacted value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createApproximateMatchFilter("userPassword", "password"),
         "Redacted approximate");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createApproximateMatchFilter(",
              "     \"userPassword\",",
              "     \"---redacted-value---\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Redacted approximate");


    // A substring filter with only a printable subInitial component.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("description", "foo", null, null),
         "Printable subInitial");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"description\",",
              "     \"foo\",",
              "     null,",
              "     null)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Printable subInitial");


    // A substring filter with only a non-printable subInitial component.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("description", testArray, null, null),
         "Non-printable subInitial");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"description\",",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     },",
              "     null,",
              "     null)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Non-printable subInitial");


    // A substring filter with only a redacted subInitial value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("userPassword", "password", null, null),
         "Redacted subInitial");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"userPassword\",",
              "     \"---redacted-subInitial---\",",
              "     null,",
              "     null)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Redacted subInitial");


    // A substring filter with only a single printable subAny component.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("description", null,
              new String[] { "foo" }, null),
         "Printable single subAny");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"description\",",
              "     null,",
              "     new String[]",
              "     {",
              "       \"foo\"",
              "     },",
              "     null)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Printable single subAny");


    // A substring filter with only a single non-printable subAny component.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("description", null,
              new byte[][] { testArray }, null),
         "Non-printable single subAny");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"description\",",
              "     null,",
              "     new byte[][]",
              "     {",
              "       new byte[]",
              "       {",
              "         0x00,",
              "         0x48, // \"H\"",
              "         0x69, // \"i\"",
              "         (byte) 0x80,",
              "         (byte) 0xff",
              "       }",
              "     },",
              "     null)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Non-printable single subAny");


    // A substring filter with only a single redacted subAny value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("userPassword", null,
              new String[] { "password" }, null),
         "Redacted single subAny");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"userPassword\",",
              "     null,",
              "     new String[]",
              "     {",
              "       \"---redacted-subAny---\"",
              "     },",
              "     null)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Redacted single subAny");


    // A substring filter with multiple printable subAny components.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("description", null,
              new String[] { "foo", "bar" }, null),
         "Printable multiple subAny");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"description\",",
              "     null,",
              "     new String[]",
              "     {",
              "       \"foo\",",
              "       \"bar\"",
              "     },",
              "     null)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Printable multiple subAny");


    // A substring filter with multiple non-printable subAny components.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("description", null,
              new byte[][] { "John".getBytes("UTF-8"), testArray }, null),
         "Non-printable multiple subAny");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"description\",",
              "     null,",
              "     new byte[][]",
              "     {",
              "       new byte[]",
              "       {",
              "         0x4a, // \"J\"",
              "         0x6f, // \"o\"",
              "         0x68, // \"h\"",
              "         0x6e // \"n\"",
              "       },",
              "       new byte[]",
              "       {",
              "         0x00,",
              "         0x48, // \"H\"",
              "         0x69, // \"i\"",
              "         (byte) 0x80,",
              "         (byte) 0xff",
              "       }",
              "     },",
              "     null)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Non-printable multiple subAny");


    // A substring filter with multiple redacted subAny values.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("userPassword", null,
              new String[] { "password1", "password2", "password3" }, null),
         "Redacted multiple subAny");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"userPassword\",",
              "     null,",
              "     new String[]",
              "     {",
              "       \"---redacted-subAny-1---\",",
              "       \"---redacted-subAny-2---\",",
              "       \"---redacted-subAny-3---\"",
              "     },",
              "     null)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Redacted multiple subAny");


    // A substring filter with only a printable subFinal component.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("description", null, null, "foo"),
         "Printable subFinal");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"description\",",
              "     null,",
              "     null,",
              "     \"foo\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Printable subFinal");


    // A substring filter with only a non-printable subFinal component.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("description", null, null, testArray),
         "Non-printable subFinal");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"description\",",
              "     null,",
              "     null,",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Non-printable subFinal");


    // A substring filter with only a redacted subFinal value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("userPassword", null, null, "password"),
         "Redacted subFinal");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"userPassword\",",
              "     null,",
              "     null,",
              "     \"---redacted-subFinal---\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Redacted subFinal");


    // A substring filter with all components as printable strings.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("description", "i",
              new String[] { "a1", "a2" }, "f"),
         "Printable all");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"description\",",
              "     \"i\",",
              "     new String[]",
              "     {",
              "       \"a1\",",
              "       \"a2\"",
              "     },",
              "     \"f\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Printable all");


    // A substring filter with all components and not all of them printable
    // strings.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("description", testArray,
              new byte[][] { "a1".getBytes("UTF-8"), "a2".getBytes("UTF-8") },
              "f".getBytes("UTF-8")),
         "Non-printable all");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"description\",",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     },",
              "     new byte[][]",
              "     {",
              "       new byte[]",
              "       {",
              "         0x61, // \"a\"",
              "         0x31 // \"1\"",
              "       },",
              "       new byte[]",
              "       {",
              "         0x61, // \"a\"",
              "         0x32 // \"2\"",
              "       }",
              "     },",
              "     new byte[]",
              "     {",
              "       0x66 // \"f\"",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Non-printable all");


    // A substring filter with all components redacted.
    helper = ToCodeArgHelper.createFilter(
         Filter.createSubstringFilter("userPassword", "i",
              new String[] { "a1", "a2" }, "f"),
         "Redacted all");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createSubstringFilter(",
              "     \"userPassword\",",
              "     \"---redacted-subInitial---\",",
              "     new String[]",
              "     {",
              "       \"---redacted-subAny-1---\",",
              "       \"---redacted-subAny-2---\"",
              "     },",
              "     \"---redacted-subFinal---\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Redacted all");


    // An extensible match filter with an attribute type and a printable value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createExtensibleMatchFilter("description", null, false, "foo"),
         "Printable attribute extensible match");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createExtensibleMatchFilter(",
              "     \"description\",",
              "     null,",
              "     false,",
              "     \"foo\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Printable attribute extensible match");


    // An extensible match filter with an attribute type and a non-printable
    // value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createExtensibleMatchFilter("description", null, false,
              testArray),
         "Non-printable attribute extensible match");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createExtensibleMatchFilter(",
              "     \"description\",",
              "     null,",
              "     false,",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(),
         "Non-printable attribute extensible match");


    // An extensible match filter with an attribute type and a redacted value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createExtensibleMatchFilter("userPassword", null, false,
              "password"),
         "Redacted attribute extensible match");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createExtensibleMatchFilter(",
              "     \"userPassword\",",
              "     null,",
              "     false,",
              "     \"---redacted-value---\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Redacted attribute extensible match");


    // An extensible match filter with a matching rule ID and a printable value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createExtensibleMatchFilter(null, "caseIgnoreMatch", true,
              "foo"),
         "Printable MR extensible match");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createExtensibleMatchFilter(",
              "     null,",
              "     \"caseIgnoreMatch\",",
              "     true,",
              "     \"foo\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Printable MR extensible match");


    // An extensible match filter with a matching rule ID and a non-printable
    // value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createExtensibleMatchFilter(null, "caseIgnoreMatch", true,
              testArray),
         "Non-printable MR extensible match");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createExtensibleMatchFilter(",
              "     null,",
              "     \"caseIgnoreMatch\",",
              "     true,",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(),
         "Non-printable MR extensible match");


    // An extensible match filter with an attribute type, matching rule ID, and
    // a printable value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createExtensibleMatchFilter("description", "caseIgnoreMatch",
              true, "foo"),
         "Printable attr and MR extensible match");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createExtensibleMatchFilter(",
              "     \"description\",",
              "     \"caseIgnoreMatch\",",
              "     true,",
              "     \"foo\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Printable attr and MR extensible match");


    // An extensible match filter with an attribute type, matching rule ID, and
    // a non-printable value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createExtensibleMatchFilter("description", "caseIgnoreMatch",
              true, testArray),
         "Non-printable attr and MR extensible match");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createExtensibleMatchFilter(",
              "     \"description\",",
              "     \"caseIgnoreMatch\",",
              "     true,",
              "     new byte[]",
              "     {",
              "       0x00,",
              "       0x48, // \"H\"",
              "       0x69, // \"i\"",
              "       (byte) 0x80,",
              "       (byte) 0xff",
              "     })"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(),
         "Non-printable attr and MR extensible match");


    // An extensible match filter with a matching rule ID and a redacted value.
    helper = ToCodeArgHelper.createFilter(
         Filter.createExtensibleMatchFilter("userPassword", "octetStringMatch",
              true, "password"),
         "Redacted attr and MR extensible match");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createExtensibleMatchFilter(",
              "     \"userPassword\",",
              "     \"octetStringMatch\",",
              "     true,",
              "     \"---redacted-value---\")"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Redacted attr and MR extensible match");


    // An AND filter with no components (aka, an LDAP true filter).
    helper = ToCodeArgHelper.createFilter(Filter.createANDFilter(),
         "LDAP true");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createANDFilter()"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "LDAP true");


    // An AND filter with a single component.
    helper = ToCodeArgHelper.createFilter(
         Filter.createANDFilter(
              Filter.createEqualityFilter("description", "foo")),
         "Single AND");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createANDFilter(",
              "     Filter.createEqualityFilter(",
              "          \"description\",",
              "          \"foo\"))"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Single AND");


    // An AND filter with multiple components.
    helper = ToCodeArgHelper.createFilter(
         Filter.createANDFilter(
              Filter.createEqualityFilter("givenName", "John"),
              Filter.createEqualityFilter("sn", "Doe")),
         "Multiple AND");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createANDFilter(",
              "     Filter.createEqualityFilter(",
              "          \"givenName\",",
              "          \"John\"),",
              "     Filter.createEqualityFilter(",
              "          \"sn\",",
              "          \"Doe\"))"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Multiple AND");


    // An OR filter with no components (aka, an LDAP false filter).
    helper = ToCodeArgHelper.createFilter(Filter.createORFilter(),
         "LDAP false");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createORFilter()"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "LDAP false");


    // An OR filter with a single component.
    helper = ToCodeArgHelper.createFilter(
         Filter.createORFilter(
              Filter.createEqualityFilter("description", "foo")),
         "Single OR");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createORFilter(",
              "     Filter.createEqualityFilter(",
              "          \"description\",",
              "          \"foo\"))"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Single OR");


    // An OR filter with multiple components.
    helper = ToCodeArgHelper.createFilter(
         Filter.createORFilter(
              Filter.createEqualityFilter("givenName", "John"),
              Filter.createEqualityFilter("sn", "Doe")),
         "Multiple OR");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createORFilter(",
              "     Filter.createEqualityFilter(",
              "          \"givenName\",",
              "          \"John\"),",
              "     Filter.createEqualityFilter(",
              "          \"sn\",",
              "          \"Doe\"))"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Multiple OR");


    // An OR filter with nested AND filters with nested equality filters.
    final String memberDN = "uid=test.user,ou=People,dc=example,dc=com";
    helper = ToCodeArgHelper.createFilter(
         Filter.createORFilter(
              Filter.createANDFilter(
                   Filter.createEqualityFilter("objectClass", "groupOfNames"),
                   Filter.createEqualityFilter("member", memberDN)),
              Filter.createANDFilter(
                   Filter.createEqualityFilter("objectClass",
                        "groupOfUniqueNames"),
                   Filter.createEqualityFilter("uniqueMember", memberDN))),
         "Group membership search");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createORFilter(",
              "     Filter.createANDFilter(",
              "          Filter.createEqualityFilter(",
              "               \"objectClass\",",
              "               \"groupOfNames\"),",
              "          Filter.createEqualityFilter(",
              "               \"member\",",
              "               \"" + memberDN + "\")),",
              "     Filter.createANDFilter(",
              "          Filter.createEqualityFilter(",
              "               \"objectClass\",",
              "               \"groupOfUniqueNames\"),",
              "          Filter.createEqualityFilter(",
              "               \"uniqueMember\",",
              "               \"" + memberDN + "\")))"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Group membership search");


    // A NOT filter with a single component.
    helper = ToCodeArgHelper.createFilter(
         Filter.createNOTFilter(
              Filter.createEqualityFilter("description", "foo")),
         "Simple NOT");
    assertNotNull(helper);

    assertEquals(helper.getLines(),
         Arrays.asList(
              "Filter.createNOTFilter(",
              "     Filter.createEqualityFilter(",
              "          \"description\",",
              "          \"foo\"))"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Simple NOT");
  }



  /**
   * Provides test coverage for the createControl method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateControl()
         throws Exception
  {
    // A null value without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createControl(null, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(Control) null");

    assertNull(helper.getComment());


    // A null value with a comment.
    helper = ToCodeArgHelper.createControl(null, "Null control");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(Control) null");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Null control");


    // A control with just an OID and a criticality of false.
    helper = ToCodeArgHelper.createControl(new Control("1.2.3.4", false),
         "Not critical no value");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Control(",
              "     \"1.2.3.4\",",
              "     false)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Not critical no value");


    // A control with just an OID and a criticality of true.
    helper = ToCodeArgHelper.createControl(new Control("1.2.3.4", true),
         "Critical no value");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Control(",
              "     \"1.2.3.4\",",
              "     true)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Critical no value");


    // A control with just an OID and a criticality of false.
    helper = ToCodeArgHelper.createControl(new Control("1.2.3.4", false),
         "Not critical no value");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Control(",
              "     \"1.2.3.4\",",
              "     false)"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Not critical no value");


    // A control with an OID, a criticality of true, and a value.
    helper = ToCodeArgHelper.createControl(
         new Control("1.2.3.4", true, new ASN1OctetString("foo")),
         "Critical with value");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Control(",
              "     \"1.2.3.4\",",
              "     true,",
              "     new ASN1OctetString(",
              "          \"foo\"))"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Critical with value");


    // A control with an OID, a criticality of false, and a value.
    final byte[] testArray =
    {
      (byte) 0x00,
      (byte) 0x48, // H
      (byte) 0x69, // i
      (byte) 0x80,
      (byte) 0xFF
    };
    helper = ToCodeArgHelper.createControl(
         new Control("1.2.3.4", false, new ASN1OctetString(testArray)),
         "Not critical with value");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Control(",
              "     \"1.2.3.4\",",
              "     false,",
              "     new ASN1OctetString(",
              "          new byte[]",
              "          {",
              "            0x00,",
              "            0x48, // \"H\"",
              "            0x69, // \"i\"",
              "            (byte) 0x80,",
              "            (byte) 0xff",
              "          }))"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Not critical with value");
  }



  /**
   * Provides test coverage for the createControlArray method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateControlArray()
         throws Exception
  {
    // A null array without a comment.
    ToCodeArgHelper helper = ToCodeArgHelper.createControlArray(null, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(Control[]) null");

    assertNull(helper.getComment());


    // A null array with a comment.
    helper = ToCodeArgHelper.createControlArray(null, "Null control array");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "(Control[]) null");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Null control array");


    // An empty array without a comment.
    helper = ToCodeArgHelper.createControlArray(StaticUtils.NO_CONTROLS, null);
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "new Control[0]");

    assertNull(helper.getComment());


    // An empty array with a comment.
    helper = ToCodeArgHelper.createControlArray(StaticUtils.NO_CONTROLS,
         "Empty array");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertFalse(helper.getLines().isEmpty());
    assertEquals(helper.getLines().size(), 1);
    assertEquals(helper.getLines().get(0), "new Control[0]");

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Empty array");


    // A single-element array with a comment.
    helper = ToCodeArgHelper.createControlArray(
         new Control[] { new Control("1.2.3.4", true) },
         "Single-element array");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Control[]",
              "{",
              "  new Control(",
              "       \"1.2.3.4\",",
              "       true)",
              "}"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Single-element array");


    // A multi-element array with a comment.
    helper = ToCodeArgHelper.createControlArray(
         new Control[]
         {
           new Control("1.2.3.4", true),
           new Control("1.2.3.5", false)
         },
         "Multi-element array");
    assertNotNull(helper);

    assertNotNull(helper.getLines());
    assertEquals(helper.getLines(),
         Arrays.asList(
              "new Control[]",
              "{",
              "  new Control(",
              "       \"1.2.3.4\",",
              "       true),",
              "  new Control(",
              "       \"1.2.3.5\",",
              "       false)",
              "}"));

    assertNotNull(helper.getComment());
    assertEquals(helper.getComment(), "Multi-element array");
  }
}
