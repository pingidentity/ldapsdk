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
package com.unboundid.ldap.sdk;



import java.util.Arrays;
import java.util.HashSet;

import org.testng.annotations.Test;

import com.unboundid.util.ByteStringBuffer;



/**
 * This class provides a set of test cases for the CompactEntry class.
 */
public class CompactEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides general test coverage for methods in the compact entry class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompactEntry()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=Test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: untypedObject",
         "objectClass: extensibleObject",
         "cn: Test",
         "booleanAttributeTrue: true",
         "booleanAttributeFalse: false",
         "dateAttribute: 20090101000000Z",
         "dnAttribute: dc=example,dc=com",
         "intAttributePositive: 1",
         "intAttributeNegative: -1",
         "intAttributeZero: 0",
         "multiValued: foo",
         "multiValued: bar",
         "withOptions: foo",
         "withOptions;lang-en-US: foo");

    CompactEntry ce = new CompactEntry(e);
    assertNotNull(ce);

    assertEquals(ce.toEntry(), e);

    assertEquals(ce.hashCode(), e.hashCode());

    assertTrue(ce.equals(new CompactEntry(e)));
    assertTrue(ce.equals(ce));
    assertFalse(ce.equals((CompactEntry) null));
    assertFalse(ce.equals(e));
    assertFalse(ce.equals("not an entry"));

    assertTrue(DN.equals(ce.getDN(), e.getDN()));

    assertEquals(ce.getParsedDN(), e.getParsedDN());

    assertEquals(ce.getRDN(), e.getRDN());

    assertEquals(ce.getParentDN(), e.getParentDN());

    assertTrue(DN.equals(ce.getParentDNString(), e.getParentDNString()));

    for (Attribute a : e.getAttributes())
    {
      assertTrue(ce.hasAttribute(a.getName()));
      assertTrue(ce.hasAttribute(a));

      for (String s : a.getValues())
      {
        assertTrue(ce.hasAttributeValue(a.getName(), s));
      }

      for (byte[] b : a.getValueByteArrays())
      {
        assertTrue(ce.hasAttributeValue(a.getName(), b));
      }

      assertEquals(ce.getAttribute(a.getName()), a);

      assertEquals(ce.getAttributeValue(a.getName()), a.getValue());

      assertTrue(Arrays.equals(ce.getAttributeValueBytes(a.getName()),
                               a.getValueByteArray()));

      if (a.getValueAsBoolean() == null)
      {
        assertEquals(ce.getAttributeValueAsBoolean(a.getName()), null);
      }
      else
      {
        assertEquals(ce.getAttributeValueAsBoolean(a.getName()),
                     a.getValueAsBoolean());
      }

      if (a.getValueAsDate() == null)
      {
        assertEquals(ce.getAttributeValueAsDate(a.getName()), null);
      }
      else
      {
        assertEquals(ce.getAttributeValueAsDate(a.getName()),
                     a.getValueAsDate());
      }

      if (a.getValueAsDN() == null)
      {
        assertEquals(ce.getAttributeValueAsDN(a.getName()), null);
      }
      else
      {
        assertEquals(ce.getAttributeValueAsDN(a.getName()),
                     a.getValueAsDN());
      }

      if (a.getValueAsInteger() == null)
      {
        assertEquals(ce.getAttributeValueAsInteger(a.getName()), null);
      }
      else
      {
        assertEquals(ce.getAttributeValueAsInteger(a.getName()),
                     a.getValueAsInteger());
      }

      if (a.getValueAsLong() == null)
      {
        assertEquals(ce.getAttributeValueAsLong(a.getName()), null);
      }
      else
      {
        assertEquals(ce.getAttributeValueAsLong(a.getName()),
                     a.getValueAsLong());
      }

      assertTrue(Arrays.equals(ce.getAttributeValues(a.getName()),
                               a.getValues()));

      assertTrue(Arrays.equals(ce.getAttributeValueByteArrays(a.getName()),
                               a.getValueByteArrays()));

      assertEquals(ce.getObjectClassAttribute(), e.getObjectClassAttribute());

      assertTrue(Arrays.equals(ce.getObjectClassValues(),
                               e.getObjectClassValues()));
    }

    assertFalse(ce.hasAttribute("missing"));
    assertFalse(ce.hasAttribute(new Attribute("missing", "missing")));
    assertFalse(ce.hasAttribute(new Attribute("cn", "missing")));
    assertFalse(ce.hasAttributeValue("missing", "missing"));
    assertFalse(ce.hasAttributeValue("cn", "missing"));
    assertFalse(ce.hasAttributeValue("missing", "missing".getBytes()));
    assertFalse(ce.hasAttributeValue("cn", "missing".getBytes()));

    assertTrue(ce.hasObjectClass("top"));
    assertTrue(ce.hasObjectClass("extensibleObject"));
    assertFalse(ce.hasObjectClass("person"));

    assertNull(ce.getAttribute("missing"));
    assertNull(ce.getAttributeValue("missing"));
    assertNull(ce.getAttributeValues("missing"));
    assertNull(ce.getAttributeValueBytes("missing"));
    assertNull(ce.getAttributeValueByteArrays("missing"));
    assertNull(ce.getAttributeValueAsBoolean("missing"));
    assertNull(ce.getAttributeValueAsDate("missing"));
    assertNull(ce.getAttributeValueAsDN("missing"));
    assertNull(ce.getAttributeValueAsInteger("missing"));
    assertNull(ce.getAttributeValueAsLong("missing"));

    assertNotNull(ce.getAttributesWithOptions("objectClass", null));
    assertFalse(ce.getAttributesWithOptions("objectClass", null).isEmpty());
    assertEquals(ce.getAttributesWithOptions("objectClass", null).size(), 1);

    assertNotNull(ce.getAttributesWithOptions("withOptions", null));
    assertFalse(ce.getAttributesWithOptions("withOptions", null).isEmpty());
    assertEquals(ce.getAttributesWithOptions("withOptions", null).size(), 2);

    HashSet<String> options = new HashSet<String>();
    assertNotNull(ce.getAttributesWithOptions("objectClass", options));
    assertFalse(ce.getAttributesWithOptions("objectClass", options).isEmpty());
    assertEquals(ce.getAttributesWithOptions("objectClass", options).size(), 1);

    assertNotNull(ce.getAttributesWithOptions("withOptions", options));
    assertFalse(ce.getAttributesWithOptions("withOptions", options).isEmpty());
    assertEquals(ce.getAttributesWithOptions("withOptions", options).size(), 2);

    options.add("lang-en-US");
    assertNotNull(ce.getAttributesWithOptions("objectClass", options));
    assertTrue(ce.getAttributesWithOptions("objectClass", options).isEmpty());
    assertEquals(ce.getAttributesWithOptions("objectClass", options).size(), 0);

    assertNotNull(ce.getAttributesWithOptions("withOptions", options));
    assertFalse(ce.getAttributesWithOptions("withOptions", options).isEmpty());
    assertEquals(ce.getAttributesWithOptions("withOptions", options).size(), 1);

    assertNotNull(ce.getAttributes());
    assertEquals(ce.getAttributes().size(), e.getAttributes().size());

    assertNotNull(ce.toLDIF());
    assertNotNull(ce.toLDIF(0));
    assertNotNull(ce.toLDIF(80));

    ce.toLDIF(new ByteStringBuffer());
    ce.toLDIF(new ByteStringBuffer(), 0);
    ce.toLDIF(new ByteStringBuffer(), 80);

    assertNotNull(ce.toLDIFString());
    assertNotNull(ce.toLDIFString(0));
    assertNotNull(ce.toLDIFString(80));

    ce.toLDIFString(new StringBuilder());
    ce.toLDIFString(new StringBuilder(), 0);
    ce.toLDIFString(new StringBuilder(), 80);

    ce.toString();
    ce.toString(new StringBuilder());

    e.addAttribute(new Attribute("noValues"));
    ce = new CompactEntry(e);
    assertTrue(ce.hasAttribute("noValues"));
    assertTrue(ce.hasAttribute(new Attribute("noValues")));
    assertFalse(ce.hasAttributeValue("noValues", "value"));
    assertNotNull(ce.getAttribute("noValues"));
    assertNull(ce.getAttributeValue("noValues"));
    assertNull(ce.getAttributeValueBytes("noValues"));
    assertNull(ce.getAttributeValueAsBoolean("noValues"));
    assertNull(ce.getAttributeValueAsDate("noValues"));
    assertNull(ce.getAttributeValueAsDN("noValues"));
    assertNull(ce.getAttributeValueAsInteger("noValues"));

    assertNotNull(ce.getAttributeValues("noValues"));
    assertEquals(ce.getAttributeValues("noValues").length, 0);

    assertNotNull(ce.getAttributeValueByteArrays("noValues"));
    assertEquals(ce.getAttributeValueByteArrays("noValues").length, 0);

    for (int i=0; i < 1500; i++)
    {
      e.addAttribute("attr-" + i, String.valueOf(i));
    }

    ce = new CompactEntry(e);
    for (int i=0; i < 1500; i++)
    {
      assertTrue(ce.hasAttribute("attr-" + i));
      assertTrue(ce.hasAttributeValue("attr-" + i, String.valueOf(i)));
    }
  }
}
