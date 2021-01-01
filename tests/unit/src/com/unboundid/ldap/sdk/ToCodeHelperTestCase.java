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



import java.util.ArrayList;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;



/**
 * This class provides a set of test cases for the {@code ToCodeHelper} class.
 */
public final class ToCodeHelperTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the generateMethodCall method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateMethodCall()
         throws Exception
  {
    // Generate a static method call that does not take any arguments and does
    // not return a value.
    final ArrayList<String> lineList = new ArrayList<String>(10);
    ToCodeHelper.generateMethodCall(lineList, 0, null, null,
         "ClassName.methodName");
    assertEquals(lineList,
         Arrays.asList("ClassName.methodName();"));


    // Do the same, but with an indent.
    lineList.clear();
    ToCodeHelper.generateMethodCall(lineList, 4, null, null,
         "ClassName.methodName");
    assertEquals(lineList,
         Arrays.asList("    ClassName.methodName();"));


    // Generate a static method call that assigns a return value to a variable.
    lineList.clear();
    ToCodeHelper.generateMethodCall(lineList, 0, "String", "returnValue",
         "ClassName.methodName");
    assertEquals(lineList,
         Arrays.asList("String returnValue = ClassName.methodName();"));


    // Do the same, but with an indent.
    lineList.clear();
    ToCodeHelper.generateMethodCall(lineList, 4, "String", "returnValue",
         "ClassName.methodName");
    assertEquals(lineList,
         Arrays.asList("    String returnValue = ClassName.methodName();"));


    // Generate a constructor that takes multiple arguments.
    lineList.clear();
    ToCodeHelper.generateMethodCall(lineList, 0, "LDAPConnection", "conn",
         "new LDAPConnection",
         ToCodeArgHelper.createString("ldap.example.com", "hostname"),
         ToCodeArgHelper.createInteger(389, "port"));
    assertEquals(lineList,
         Arrays.asList(
              "LDAPConnection conn = new LDAPConnection(",
              "     \"ldap.example.com\", // hostname",
              "     389); // port"));
  }



  /**
   * Provides test coverage for the generateVariableAssignment method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateVariableAssignment()
         throws Exception
  {
    // Generate a simple string assignment to a null value.
    final ArrayList<String> lineList = new ArrayList<String>(10);
    ToCodeHelper.generateVariableAssignment(lineList, 0, "String", "nullString",
         ToCodeArgHelper.createString(null, "Null Value"));
    assertEquals(lineList,
         Arrays.asList("String nullString = (String) null; // Null Value"));


    // Generate a simple string assignment to a non-null value.
    lineList.clear();
    ToCodeHelper.generateVariableAssignment(lineList, 0, "String",
         "nonNullString",
         ToCodeArgHelper.createString("foo", "Non-Null Value"));
    assertEquals(lineList,
         Arrays.asList("String nonNullString = \"foo\"; // Non-Null Value"));


    // Generate an assignment to a byte array.
    final byte[] testArray =
    {
      (byte) 0x00,
      (byte) 0x48, // H
      (byte) 0x69, // i
      (byte) 0x80,
      (byte) 0xFF
    };
    lineList.clear();
    ToCodeHelper.generateVariableAssignment(lineList, 4, "byte[]", "byteArray",
         ToCodeArgHelper.createByteArray(testArray, true, "Look at this"));
    assertEquals(lineList,
         Arrays.asList(
              "    byte[] byteArray = new byte[] // Look at this",
              "    {",
              "      0x00,",
              "      0x48, // \"H\"",
              "      0x69, // \"i\"",
              "      (byte) 0x80,",
              "      (byte) 0xff",
              "    };"));


    // Generate an assignment to an ASN.1 octet string with a custom type and a
    // byte array value.
    lineList.clear();
    ToCodeHelper.generateVariableAssignment(lineList, 4, "ASN1OctetString", "s",
         ToCodeArgHelper.createASN1OctetString(
              new ASN1OctetString((byte) 0x81, testArray), "And this"));
    assertEquals(lineList,
         Arrays.asList(
              "    ASN1OctetString s = new ASN1OctetString( // And this",
              "         (byte) 0x81,",
              "         new byte[]",
              "         {",
              "           0x00,",
              "           0x48, // \"H\"",
              "           0x69, // \"i\"",
              "           (byte) 0x80,",
              "           (byte) 0xff",
              "         });"));
  }
}
