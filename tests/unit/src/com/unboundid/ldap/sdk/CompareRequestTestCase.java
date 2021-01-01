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
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the CompareRequest class.
 */
public class CompareRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which takes string arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "description", "foo");
    compareRequest = compareRequest.duplicate();

    assertNotNull(compareRequest.getDN());
    assertEquals(compareRequest.getDN(), "dc=example,dc=com");

    assertNotNull(compareRequest.getAttributeName());
    assertEquals(compareRequest.getAttributeName(), "description");

    assertNotNull(compareRequest.getAssertionValue());
    assertEquals(compareRequest.getAssertionValue(), "foo");

    assertNotNull(compareRequest.getAssertionValueBytes());
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
                             "foo".getBytes("UTF-8")));

    assertFalse(compareRequest.hasControl());
    assertFalse(compareRequest.hasControl("1.2.3.4"));
    assertNull(compareRequest.getControl("1.2.3.4"));
    assertNotNull(compareRequest.getControls());
    assertEquals(compareRequest.getControls().length, 0);

    assertNotNull(compareRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    compareRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    compareRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(compareRequest);

    assertNull(compareRequest.getIntermediateResponseListener());
    compareRequest.setIntermediateResponseListener(
         new TestIntermediateResponseListener());
    assertNotNull(compareRequest.getIntermediateResponseListener());
    compareRequest.setIntermediateResponseListener(null);
    assertNull(compareRequest.getIntermediateResponseListener());
  }



  /**
   * Tests the first constructor, which takes string arguments, using
   * {@code null} values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1Null()
         throws Exception
  {
    new CompareRequest((String) null, (String) null, (String) null);
  }



  /**
   * Tests the second constructor, which takes string DN and attribute name and
   * byte array assertion value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "description",
                            "foo".getBytes("UTF-8"));
    compareRequest = compareRequest.duplicate();

    assertNotNull(compareRequest.getDN());
    assertEquals(compareRequest.getDN(), "dc=example,dc=com");

    assertNotNull(compareRequest.getAttributeName());
    assertEquals(compareRequest.getAttributeName(), "description");

    assertNotNull(compareRequest.getAssertionValue());
    assertEquals(compareRequest.getAssertionValue(), "foo");

    assertNotNull(compareRequest.getAssertionValueBytes());
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
                             "foo".getBytes("UTF-8")));

    assertFalse(compareRequest.hasControl());
    assertFalse(compareRequest.hasControl("1.2.3.4"));
    assertNull(compareRequest.getControl("1.2.3.4"));
    assertNotNull(compareRequest.getControls());
    assertEquals(compareRequest.getControls().length, 0);

    assertNotNull(compareRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    compareRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    compareRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(compareRequest);
  }



  /**
   * Tests the second constructor, which takes string DN and attribute name and
   * byte array assertion value, using {@code null values}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2Null()
         throws Exception
  {
    new CompareRequest((String) null, (String) null, (byte[]) null);
  }



  /**
   * Tests the third constructor, which takes a DN object and string attribute
   * name and assertion value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    CompareRequest compareRequest =
         new CompareRequest(new DN("dc=example,dc=com"), "description", "foo");
    compareRequest = compareRequest.duplicate();

    assertNotNull(compareRequest.getDN());
    assertEquals(compareRequest.getDN(), "dc=example,dc=com");

    assertNotNull(compareRequest.getAttributeName());
    assertEquals(compareRequest.getAttributeName(), "description");

    assertNotNull(compareRequest.getAssertionValue());
    assertEquals(compareRequest.getAssertionValue(), "foo");

    assertNotNull(compareRequest.getAssertionValueBytes());
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
                             "foo".getBytes("UTF-8")));

    assertFalse(compareRequest.hasControl());
    assertFalse(compareRequest.hasControl("1.2.3.4"));
    assertNull(compareRequest.getControl("1.2.3.4"));
    assertNotNull(compareRequest.getControls());
    assertEquals(compareRequest.getControls().length, 0);

    assertNotNull(compareRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    compareRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    compareRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(compareRequest);
  }



  /**
   * Tests the third constructor, which takes a DN object and string attribute
   * name and assertion value, using {@code null} values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3Null()
         throws Exception
  {
    new CompareRequest((DN) null, (String) null, (String) null);
  }



  /**
   * Tests the fourth constructor, which takes a DN object, a string attribute
   * name and byte array assertion value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    CompareRequest compareRequest =
         new CompareRequest(new DN("dc=example,dc=com"), "description",
                            "foo".getBytes("UTF-8"));
    compareRequest = compareRequest.duplicate();

    assertNotNull(compareRequest.getDN());
    assertEquals(compareRequest.getDN(), "dc=example,dc=com");

    assertNotNull(compareRequest.getAttributeName());
    assertEquals(compareRequest.getAttributeName(), "description");

    assertNotNull(compareRequest.getAssertionValue());
    assertEquals(compareRequest.getAssertionValue(), "foo");

    assertNotNull(compareRequest.getAssertionValueBytes());
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
                             "foo".getBytes("UTF-8")));

    assertFalse(compareRequest.hasControl());
    assertFalse(compareRequest.hasControl("1.2.3.4"));
    assertNull(compareRequest.getControl("1.2.3.4"));
    assertNotNull(compareRequest.getControls());
    assertEquals(compareRequest.getControls().length, 0);

    assertNotNull(compareRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    compareRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    compareRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(compareRequest);
  }



  /**
   * Tests the fourth constructor, which takes DN object, a string attribute
   * name and byte array assertion value, using {@code null values}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4Null()
         throws Exception
  {
    new CompareRequest((DN) null, (String) null, (byte[]) null);
  }



  /**
   * Tests the fifth constructor, which takes string arguments and set of
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "description", "foo",
                            controls);
    compareRequest = compareRequest.duplicate();

    assertNotNull(compareRequest.getDN());
    assertEquals(compareRequest.getDN(), "dc=example,dc=com");

    assertNotNull(compareRequest.getAttributeName());
    assertEquals(compareRequest.getAttributeName(), "description");

    assertNotNull(compareRequest.getAssertionValue());
    assertEquals(compareRequest.getAssertionValue(), "foo");

    assertNotNull(compareRequest.getAssertionValueBytes());
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
                             "foo".getBytes("UTF-8")));

    assertTrue(compareRequest.hasControl());
    assertTrue(compareRequest.hasControl("1.2.3.4"));
    assertNotNull(compareRequest.getControl("1.2.3.4"));
    assertFalse(compareRequest.hasControl("1.2.3.6"));
    assertNull(compareRequest.getControl("1.2.3.6"));
    assertNotNull(compareRequest.getControls());
    assertEquals(compareRequest.getControls().length, 2);

    assertNotNull(compareRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    compareRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    compareRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(compareRequest);
  }



  /**
   * Tests the sixth constructor, which takes string DN and attribute name,
   * byte array assertion value, and set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "description",
                            "foo".getBytes("UTF-8"), controls);
    compareRequest = compareRequest.duplicate();

    assertNotNull(compareRequest.getDN());
    assertEquals(compareRequest.getDN(), "dc=example,dc=com");

    assertNotNull(compareRequest.getAttributeName());
    assertEquals(compareRequest.getAttributeName(), "description");

    assertNotNull(compareRequest.getAssertionValue());
    assertEquals(compareRequest.getAssertionValue(), "foo");

    assertNotNull(compareRequest.getAssertionValueBytes());
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
                             "foo".getBytes("UTF-8")));

    assertTrue(compareRequest.hasControl());
    assertTrue(compareRequest.hasControl("1.2.3.4"));
    assertNotNull(compareRequest.getControl("1.2.3.4"));
    assertFalse(compareRequest.hasControl("1.2.3.6"));
    assertNull(compareRequest.getControl("1.2.3.6"));
    assertNotNull(compareRequest.getControls());
    assertEquals(compareRequest.getControls().length, 2);

    assertNotNull(compareRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    compareRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    compareRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(compareRequest);
  }



  /**
   * Tests the seventh constructor, which takes a DN object, string attribute
   * name and assertion value, and set of controls.
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

    CompareRequest compareRequest =
         new CompareRequest(new DN("dc=example,dc=com"), "description", "foo",
                            controls);
    compareRequest = compareRequest.duplicate();

    assertNotNull(compareRequest.getDN());
    assertEquals(compareRequest.getDN(), "dc=example,dc=com");

    assertNotNull(compareRequest.getAttributeName());
    assertEquals(compareRequest.getAttributeName(), "description");

    assertNotNull(compareRequest.getAssertionValue());
    assertEquals(compareRequest.getAssertionValue(), "foo");

    assertNotNull(compareRequest.getAssertionValueBytes());
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
                             "foo".getBytes("UTF-8")));

    assertTrue(compareRequest.hasControl());
    assertTrue(compareRequest.hasControl("1.2.3.4"));
    assertNotNull(compareRequest.getControl("1.2.3.4"));
    assertFalse(compareRequest.hasControl("1.2.3.6"));
    assertNull(compareRequest.getControl("1.2.3.6"));
    assertNotNull(compareRequest.getControls());
    assertEquals(compareRequest.getControls().length, 2);

    assertNotNull(compareRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    compareRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    compareRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(compareRequest);
  }



  /**
   * Tests the eighth constructor, which takes a DN object, a string attribute
   * name, an ASN.1 octet string assertion value, and set of controls.
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

    CompareRequest compareRequest =
         new CompareRequest(new DN("dc=example,dc=com"), "description",
              new ASN1OctetString("jalape\\c3\\b1o"), controls);
    compareRequest = compareRequest.duplicate();

    assertNotNull(compareRequest.getDN());
    assertEquals(compareRequest.getDN(), "dc=example,dc=com");

    assertNotNull(compareRequest.getAttributeName());
    assertEquals(compareRequest.getAttributeName(), "description");

    assertNotNull(compareRequest.getAssertionValue());
    assertEquals(compareRequest.getAssertionValue(), "jalape\\c3\\b1o");

    assertNotNull(compareRequest.getAssertionValueBytes());
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
         "jalape\\c3\\b1o".getBytes("UTF-8")));

    assertTrue(compareRequest.hasControl());
    assertTrue(compareRequest.hasControl("1.2.3.4"));
    assertNotNull(compareRequest.getControl("1.2.3.4"));
    assertFalse(compareRequest.hasControl("1.2.3.6"));
    assertNull(compareRequest.getControl("1.2.3.6"));
    assertNotNull(compareRequest.getControls());
    assertEquals(compareRequest.getControls().length, 2);

    assertNotNull(compareRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    compareRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    compareRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(compareRequest);
  }



  /**
   * Tests the ninth constructor, which takes a DN object, a string attribute
   * name, a byte array assertion value, and set of controls.
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

    CompareRequest compareRequest =
         new CompareRequest(new DN("dc=example,dc=com"), "userPassword",
                            "password".getBytes("UTF-8"), controls);
    compareRequest = compareRequest.duplicate();

    assertNotNull(compareRequest.getDN());
    assertEquals(compareRequest.getDN(), "dc=example,dc=com");

    assertNotNull(compareRequest.getAttributeName());
    assertEquals(compareRequest.getAttributeName(), "userPassword");

    assertNotNull(compareRequest.getAssertionValue());
    assertEquals(compareRequest.getAssertionValue(), "password");

    assertNotNull(compareRequest.getAssertionValueBytes());
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
                             "password".getBytes("UTF-8")));

    assertTrue(compareRequest.hasControl());
    assertTrue(compareRequest.hasControl("1.2.3.4"));
    assertNotNull(compareRequest.getControl("1.2.3.4"));
    assertFalse(compareRequest.hasControl("1.2.3.6"));
    assertNull(compareRequest.getControl("1.2.3.6"));
    assertNotNull(compareRequest.getControls());
    assertEquals(compareRequest.getControls().length, 2);

    assertNotNull(compareRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    compareRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    compareRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(compareRequest);
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
    CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "description", "foo");
    assertEquals(compareRequest.getDN(), "dc=example,dc=com");

    compareRequest.setDN("o=example.com");
    assertEquals(compareRequest.getDN(), "o=example.com");

    compareRequest.setDN(new DN("o=example.net"));
    assertEquals(compareRequest.getDN(), "o=example.net");

    testEncoding(compareRequest);
  }



  /**
   * Tests the {@code getAttributeName} and {@code setAttributeName} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetAttributeName()
         throws Exception
  {
    CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "description", "foo");
    assertEquals(compareRequest.getAttributeName(), "description");

    compareRequest.setAttributeName("displayName");
    assertEquals(compareRequest.getAttributeName(), "displayName");

    testEncoding(compareRequest);
  }



  /**
   * Tests the {@code getAssertionValue} and {@code setAssertionValue} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetAssertionValue()
         throws Exception
  {
    CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "description", "foo");
    assertEquals(compareRequest.getAssertionValue(), "foo");
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
                             "foo".getBytes("UTF-8")));
    assertEquals(compareRequest.getRawAssertionValue(),
                 new ASN1OctetString("foo"));

    compareRequest.setAssertionValue("bar");
    assertEquals(compareRequest.getAssertionValue(), "bar");
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
                             "bar".getBytes("UTF-8")));
    assertEquals(compareRequest.getRawAssertionValue(),
                 new ASN1OctetString("bar"));

    compareRequest.setAssertionValue("baz".getBytes("UTF-8"));
    assertEquals(compareRequest.getAssertionValue(), "baz");
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
                             "baz".getBytes("UTF-8")));
    assertEquals(compareRequest.getRawAssertionValue(),
                 new ASN1OctetString("baz"));

    compareRequest.setAssertionValue(new ASN1OctetString("bat"));
    assertEquals(compareRequest.getAssertionValue(), "bat");
    assertTrue(Arrays.equals(compareRequest.getAssertionValueBytes(),
                             "bat".getBytes("UTF-8")));
    assertEquals(compareRequest.getRawAssertionValue(),
                 new ASN1OctetString("bat"));

    testEncoding(compareRequest);
  }



  /**
   * Tests to ensure that the encoding for the provided compare request is
   * identical when using the stream-based and non-stream-based ASN.1 encoding
   * mechanisms.
   *
   * @param  compareRequest  The compare request to be tested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void testEncoding(final CompareRequest compareRequest)
          throws Exception
  {
    ASN1Element protocolOpElement = compareRequest.encodeProtocolOp();

    ASN1Buffer b = new ASN1Buffer();
    compareRequest.writeTo(b);

    assertTrue(Arrays.equals(b.toByteArray(), protocolOpElement.encode()));
  }
}
