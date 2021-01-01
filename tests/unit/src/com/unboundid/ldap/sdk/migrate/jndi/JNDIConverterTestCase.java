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
package com.unboundid.ldap.sdk.migrate.jndi;



import java.util.Arrays;
import java.util.LinkedList;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.BasicControl;
import javax.naming.ldap.ExtendedResponse;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the {@code JNDIConverter} class.
 */
public class JNDIConverterTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the method used to convert a non-{@code null}
   * JNDI attribute to an SDK attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKAttribute()
         throws Exception
  {
    BasicAttribute jndiAttr = new BasicAttribute("a");
    jndiAttr.add("b");
    jndiAttr.add("c".getBytes());

    Attribute sdkAttr = JNDIConverter.convertAttribute(jndiAttr);

    assertNotNull(sdkAttr);

    assertNotNull(sdkAttr.getName());
    assertEquals(sdkAttr.getName(), "a");

    assertNotNull(sdkAttr.getValues());
    assertEquals(sdkAttr.getValues().length, 2);
    assertFalse(sdkAttr.hasValue("a"));
    assertTrue(sdkAttr.hasValue("b"));
    assertTrue(sdkAttr.hasValue("c"));
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} JNDI
   * attribute to an SDK attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullSDKAttribute()
         throws Exception
  {
    assertNull(JNDIConverter.convertAttribute((BasicAttribute) null));
  }



  /**
   * Provides test coverage for the method used to convert a non-{@code null}
   * SDK attribute to a JNDI attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDIAttribute()
         throws Exception
  {
    Attribute sdkAttr = new Attribute("a", "b", "c");

    javax.naming.directory.Attribute jndiAttr =
         JNDIConverter.convertAttribute(sdkAttr);

    assertNotNull(jndiAttr);

    assertNotNull(jndiAttr.getID());
    assertEquals(jndiAttr.getID(), "a");

    NamingEnumeration<?> values = jndiAttr.getAll();

    boolean bFound = false;
    boolean cFound = false;
    while (values.hasMoreElements())
    {
      String s;
      Object v = values.nextElement();
      if (v instanceof byte[])
      {
        s = StaticUtils.toUTF8String((byte[]) v);
      }
      else
      {
        s = String.valueOf(v);
      }

      if (s.equals("b"))
      {
        bFound = true;
      }
      else if (s.equals("c"))
      {
        cFound = true;
      }
      else
      {
        fail("Unexpected value " + s);
      }
    }

    values.close();

    assertTrue(bFound);
    assertTrue(cFound);
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} SDK
   * attribute to a JNDI attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullJNDIAttribute()
         throws Exception
  {
    assertNull(JNDIConverter.convertAttribute((Attribute) null));
  }



  /**
   * Provides test coverage for the method used to convert non-empty JNDI
   * attributes to an array of SDK attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKAttributes()
         throws Exception
  {
    BasicAttributes jndiAttrs = new BasicAttributes();
    jndiAttrs.put(new BasicAttribute("a", "1"));
    jndiAttrs.put(new BasicAttribute("b", "2"));

    Attribute[] sdkAttrs = JNDIConverter.convertAttributes(jndiAttrs);

    assertNotNull(sdkAttrs);
    assertEquals(sdkAttrs.length, 2);

    boolean aFound = false;
    boolean bFound = false;
    for (Attribute a : sdkAttrs)
    {
      if (a.getName().equals("a"))
      {
        aFound =  true;
      }
      else if (a.getName().equals("b"))
      {
        bFound =  true;
      }
      else
      {
        fail("Unexpected attribute "  + a.getName());
      }
    }

    assertTrue(aFound);
    assertTrue(bFound);
  }



  /**
   * Provides test coverage for the method used to convert empty JNDI attributes
   * to an array of SDK attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToEmptySDKAttributes()
         throws Exception
  {
    Attribute[] sdkAttrs =
         JNDIConverter.convertAttributes(new BasicAttributes());

    assertNotNull(sdkAttrs);
    assertEquals(sdkAttrs.length, 0);
  }



  /**
   * Provides test coverage for the method used to convert {@code null} JNDI
   * attributes to an array of SDK attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullSDKAttributes()
         throws Exception
  {
    Attribute[] sdkAttrs =
         JNDIConverter.convertAttributes((BasicAttributes) null);

    assertNotNull(sdkAttrs);
    assertEquals(sdkAttrs.length, 0);
  }



  /**
   * Provides test coverage for the method used to convert a non-empty array of
   * SDK attributes to JNDI attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDIAttributesArray()
         throws Exception
  {
    Attributes jndiAttrs = JNDIConverter.convertAttributes(
         new Attribute("a", "1"),
         new Attribute("b", "2"));

    assertNotNull(jndiAttrs);
    assertEquals(jndiAttrs.size(), 2);

    boolean aFound = false;
    boolean bFound = false;

    NamingEnumeration<? extends javax.naming.directory.Attribute> attrs =
         jndiAttrs.getAll();

    while (attrs.hasMoreElements())
    {
      javax.naming.directory.Attribute a = attrs.nextElement();
      if (a.getID().equals("a"))
      {
        aFound = true;
      }
      else if (a.getID().equals("b"))
      {
        bFound = true;
      }
      else
      {
        fail("Unexpected attribute " + a.getID());
      }
    }

    attrs.close();

    assertTrue(aFound);
    assertTrue(bFound);
  }



  /**
   * Provides test coverage for the method used to convert an empty array of SDK
   * attributes to JNDI attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToEmptyJNDIAttributesArray()
         throws Exception
  {
    Attributes jndiAttrs = JNDIConverter.convertAttributes(new Attribute[0]);

    assertNotNull(jndiAttrs);
    assertEquals(jndiAttrs.size(), 0);
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} array
   * of SDK attributes to JNDI attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullJNDIAttributesArray()
         throws Exception
  {
    Attributes jndiAttrs = JNDIConverter.convertAttributes((Attribute[]) null);

    assertNotNull(jndiAttrs);
    assertEquals(jndiAttrs.size(), 0);
  }



  /**
   * Provides test coverage for the method used to convert a non-empty
   * collection of SDK attributes to JNDI attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDIAttributesCollection()
         throws Exception
  {
    Attributes jndiAttrs = JNDIConverter.convertAttributes(Arrays.asList(
         new Attribute("a", "1"),
         new Attribute("b", "2")));

    assertNotNull(jndiAttrs);
    assertEquals(jndiAttrs.size(), 2);

    boolean aFound = false;
    boolean bFound = false;

    NamingEnumeration<? extends javax.naming.directory.Attribute> attrs =
         jndiAttrs.getAll();

    while (attrs.hasMoreElements())
    {
      javax.naming.directory.Attribute a = attrs.nextElement();
      if (a.getID().equals("a"))
      {
        aFound = true;
      }
      else if (a.getID().equals("b"))
      {
        bFound = true;
      }
      else
      {
        fail("Unexpected attribute " + a.getID());
      }
    }

    attrs.close();

    assertTrue(aFound);
    assertTrue(bFound);
  }



  /**
   * Provides test coverage for the method used to convert an empty collection
   * of SDK attributes to JNDI attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToEmptyJNDIAttributesCollection()
         throws Exception
  {
    Attributes jndiAttrs =
         JNDIConverter.convertAttributes(new LinkedList<Attribute>());

    assertNotNull(jndiAttrs);
    assertEquals(jndiAttrs.size(), 0);
  }



  /**
   * Provides test coverage for the method used to convert a {@code null}
   * collection of SDK attributes to JNDI attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullJNDIAttributesCollection()
         throws Exception
  {
    Attributes jndiAttrs =
         JNDIConverter.convertAttributes((LinkedList<Attribute>) null);

    assertNotNull(jndiAttrs);
    assertEquals(jndiAttrs.size(), 0);
  }



  /**
   * Provides test coverage for the method used to convert a non-{@code null}
   * JNDI control to an SDK control for a control which does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKControlWithoutValue()
         throws Exception
  {
    BasicControl jndiControl = new BasicControl("1.2.3.4", false, null);

    Control sdkControl = JNDIConverter.convertControl(jndiControl);

    assertNotNull(sdkControl);

    assertNotNull(sdkControl.getOID());
    assertEquals(sdkControl.getOID(), "1.2.3.4");

    assertFalse(sdkControl.isCritical());

    assertNull(sdkControl.getValue());
  }



  /**
   * Provides test coverage for the method used to convert a non-{@code null}
   * JNDI control to an SDK control for a control which has a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKControlWithValue()
         throws Exception
  {
    BasicControl jndiControl = new BasicControl("1.2.3.4", true,
         new ASN1OctetString("foo").encode());

    Control sdkControl = JNDIConverter.convertControl(jndiControl);

    assertNotNull(sdkControl);

    assertNotNull(sdkControl.getOID());
    assertEquals(sdkControl.getOID(), "1.2.3.4");

    assertTrue(sdkControl.isCritical());

    assertNotNull(sdkControl.getValue());
    assertEquals(sdkControl.getValue().stringValue(), "foo");
  }



  /**
   * Provides test coverage for the method used to convert a non-{@code null}
   * JNDI control to an SDK control for a control which has a malformed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NamingException.class })
  public void testToSDKControlWithMalformedValue()
         throws Exception
  {
    BasicControl jndiControl = new BasicControl("1.2.3.4", true,
         new byte[] { (byte) 0x01 });

    JNDIConverter.convertControl(jndiControl);
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} JNDI
   * control to an SDK control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullSDKControl()
       throws Exception
  {
    assertNull(JNDIConverter.convertControl((BasicControl) null));
  }



  /**
   * Provides test coverage for the method used to convert a non-{@code null}
   * SDK control to a JNDI control for a control which does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDIControlWithoutValue()
         throws Exception
  {
    Control sdkControl = new Control("1.2.3.4", false, null);

    javax.naming.ldap.Control jndiControl =
         JNDIConverter.convertControl(sdkControl);

    assertNotNull(jndiControl);

    assertNotNull(jndiControl.getID());
    assertEquals(jndiControl.getID(), "1.2.3.4");

    assertFalse(jndiControl.isCritical());

    assertNull(jndiControl.getEncodedValue());
  }



  /**
   * Provides test coverage for the method used to convert a non-{@code null}
   * SDK control to a JNDI control for a control which has a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDIControlWithValue()
         throws Exception
  {
    Control sdkControl =
         new Control("1.2.3.4", true, new ASN1OctetString("foo"));

    javax.naming.ldap.Control jndiControl =
         JNDIConverter.convertControl(sdkControl);

    assertNotNull(jndiControl);

    assertNotNull(jndiControl.getID());
    assertEquals(jndiControl.getID(), "1.2.3.4");

    assertTrue(jndiControl.isCritical());

    assertNotNull(jndiControl.getEncodedValue());
    assertTrue(Arrays.equals(jndiControl.getEncodedValue(),
         new ASN1OctetString("foo").encode()));
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} SDK
   * control to a JNDI control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullJNDIControl()
         throws Exception
  {
    assertNull(JNDIConverter.convertControl((Control) null));
  }



  /**
   * Provides test coverage for the method used to convert a non-empty array of
   * JNDI controls to an array of SDK controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKControls()
         throws Exception
  {
    Control[] sdkControls = JNDIConverter.convertControls(
         new BasicControl("1.2.3.4", false, null),
         new BasicControl("1.2.3.5", true,
              new ASN1OctetString("foo").encode()));

    assertNotNull(sdkControls);

    assertEquals(sdkControls.length, 2);

    assertEquals(sdkControls[0].getOID(), "1.2.3.4");

    assertEquals(sdkControls[1].getOID(), "1.2.3.5");
  }



  /**
   * Provides test coverage for the method used to convert an empty array of
   * JNDI controls to an array of SDK controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToEmptySDKControls()
         throws Exception
  {
    Control[] sdkControls = JNDIConverter.convertControls(new BasicControl[0]);

    assertNotNull(sdkControls);

    assertEquals(sdkControls.length, 0);
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} array
   * of JNDI controls to an array of SDK controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullSDKControls()
         throws Exception
  {
    Control[] sdkControls =
         JNDIConverter.convertControls((BasicControl[]) null);

    assertNotNull(sdkControls);

    assertEquals(sdkControls.length, 0);
  }



  /**
   * Provides test coverage for the method used to convert a non-empty array of
   * SDK controls to an array of JNDI controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDIControls()
         throws Exception
  {
    javax.naming.ldap.Control[] jndiControls = JNDIConverter.convertControls(
         new Control("1.2.3.4", false, null),
         new Control("1.2.3.5", true, new ASN1OctetString("foo")));

    assertNotNull(jndiControls);

    assertEquals(jndiControls.length, 2);

    assertEquals(jndiControls[0].getID(), "1.2.3.4");

    assertEquals(jndiControls[1].getID(), "1.2.3.5");
  }



  /**
   * Provides test coverage for the method used to convert an empty array of SDK
   * controls to an array of JNDI controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToEmptyJNDIControls()
         throws Exception
  {
    javax.naming.ldap.Control[] jndiControls =
         JNDIConverter.convertControls(new Control[0]);

    assertNotNull(jndiControls);

    assertEquals(jndiControls.length, 0);
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} array
   * of SDK controls to an array of JNDI controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullJNDIControls()
         throws Exception
  {
    javax.naming.ldap.Control[] jndiControls =
         JNDIConverter.convertControls((Control[]) null);

    assertNotNull(jndiControls);

    assertEquals(jndiControls.length, 0);
  }



  /**
   * Provides test coverage for the method used to convert a JNDI extended
   * request to an SDK extended request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKExtendedRequest()
         throws Exception
  {
    TestExtendedRequest jndiRequest = new TestExtendedRequest("1.2.3.4",
         new ASN1OctetString("foo").encode());

    ExtendedRequest sdkRequest =
         JNDIConverter.convertExtendedRequest(jndiRequest);

    assertNotNull(sdkRequest);

    assertNotNull(sdkRequest.getOID());
    assertEquals(sdkRequest.getOID(), "1.2.3.4");

    assertNotNull(sdkRequest.getValue());
    assertEquals(sdkRequest.getValue(), new ASN1OctetString("foo"));
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} JNDI
   * extended request to an SDK extended request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullSDKExtendedRequest()
         throws Exception
  {
    assertNull(JNDIConverter.convertExtendedRequest(
         (TestExtendedRequest) null));
  }



  /**
   * Provides test coverage for the method used to convert an SDK extended
   * request to a JNDI extended request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDIExtendedRequest()
         throws Exception
  {
    ExtendedRequest sdkRequest =
         new ExtendedRequest("1.2.3.4", new ASN1OctetString("foo"));

    javax.naming.ldap.ExtendedRequest jndiRequest =
         JNDIConverter.convertExtendedRequest(sdkRequest);

    assertNotNull(jndiRequest);

    assertNotNull(jndiRequest.getID());
    assertEquals(jndiRequest.getID(), "1.2.3.4");

    assertNotNull(jndiRequest.getEncodedValue());
    assertTrue(Arrays.equals(jndiRequest.getEncodedValue(),
         new ASN1OctetString("foo").encode()));
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} SDK
   * extended request to a JNDI extended request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullJNDIExtendedRequest()
         throws Exception
  {
    assertNull(JNDIConverter.convertExtendedRequest((ExtendedRequest) null));
  }



  /**
   * Provides test coverage for the method used to convert a JNDI extended
   * response to an SDK extended result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKExtendedResult()
         throws Exception
  {
    TestExtendedResponse jndiResponse =
         new TestExtendedResponse("1.2.3.4", null, 0, 0);

    ExtendedResult sdkResult =
         JNDIConverter.convertExtendedResponse(jndiResponse);

    assertNotNull(sdkResult);

    assertNotNull(sdkResult.getOID());
    assertEquals(sdkResult.getOID(), "1.2.3.4");

    assertNull(sdkResult.getValue());
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} JNDI
   * extended response to an SDK extended result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullSDKExtendedResult()
         throws Exception
  {
    assertNull(JNDIConverter.convertExtendedResponse(null));
  }



  /**
   * Provides test coverage for the method used to convert an SDK extended
   * result to a JNDI extended response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDIExtendedResponse()
         throws Exception
  {
    ExtendedResult sdkResult = new ExtendedResult(-1, ResultCode.SUCCESS, null,
         null, null, "1.2.3.4", null, null);

    ExtendedResponse jndiResponse =
         JNDIConverter.convertExtendedResult(sdkResult);

    assertNotNull(jndiResponse);

    assertNotNull(jndiResponse.getID());
    assertEquals(jndiResponse.getID(), "1.2.3.4");

    assertNull(jndiResponse.getEncodedValue());
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} SDK
   * extended result to a JNDI extended response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullJNDIExtendedResponse()
         throws Exception
  {
    assertNull(JNDIConverter.convertExtendedResult(null));
  }



  /**
   * Provides test coverage for the method used to convert a JNDI modification
   * item to an SDK modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKModification()
         throws Exception
  {
    ModificationItem jndiMod = new ModificationItem(
         DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("foo", "bar"));

    Modification sdkMod = JNDIConverter.convertModification(jndiMod);

    assertNotNull(sdkMod);

    assertNotNull(sdkMod.getModificationType());
    assertEquals(sdkMod.getModificationType(), ModificationType.REPLACE);

    assertNotNull(sdkMod.getAttributeName());
    assertEquals(sdkMod.getAttributeName(), "foo");
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} JNDI
   * modification item to an SDK modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullSDKModification()
         throws Exception
  {
    assertNull(JNDIConverter.convertModification((ModificationItem) null));
  }



  /**
   * Provides test coverage for the method used to convert an SDK modification
   * to a JNDI modification item.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDIModificationItem()
         throws Exception
  {
    Modification sdkMod =
         new Modification(ModificationType.REPLACE, "foo", "bar");

    ModificationItem jndiMod = JNDIConverter.convertModification(sdkMod);

    assertNotNull(jndiMod);

    assertEquals(jndiMod.getModificationOp(), 2);

    assertNotNull(jndiMod.getAttribute());
    assertEquals(jndiMod.getAttribute().getID(), "foo");
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} SDK
   * modification to a JNDI modification item.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullJNDIModificationItem()
         throws Exception
  {
    assertNull(JNDIConverter.convertModification((Modification) null));
  }



  /**
   * Provides test coverage for the method used to convert an SDK modification
   * with an invalid modification type to a JNDI modification item.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NamingException.class })
  public void testToJNDIModificationItemInvalidModificationType()
         throws Exception
  {
    Modification sdkMod =
         new Modification(ModificationType.valueOf(12345), "foo", "bar");

    JNDIConverter.convertModification(sdkMod);
  }



  /**
   * Provides test coverage for the method used to convert a non-empty array of
   * JNDI modification items to an array of SDK modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKModifications()
         throws Exception
  {
    Modification[] sdkMods = JNDIConverter.convertModifications(
         new ModificationItem(DirContext.ADD_ATTRIBUTE,
              new BasicAttribute("a", "1")),
         new ModificationItem(DirContext.REMOVE_ATTRIBUTE,
              new BasicAttribute("b", "2")),
         new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
              new BasicAttribute("c", "3")));

    assertNotNull(sdkMods);

    assertEquals(sdkMods.length, 3);

    assertEquals(sdkMods[0].getModificationType(), ModificationType.ADD);
    assertEquals(sdkMods[0].getAttributeName(), "a");

    assertEquals(sdkMods[1].getModificationType(), ModificationType.DELETE);
    assertEquals(sdkMods[1].getAttributeName(), "b");

    assertEquals(sdkMods[2].getModificationType(), ModificationType.REPLACE);
    assertEquals(sdkMods[2].getAttributeName(), "c");
  }



  /**
   * Provides test coverage for the method used to convert an empty array of
   * JNDI modification items to an array of SDK modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToEmptySDKModifications()
         throws Exception
  {
    Modification[] sdkMods =
         JNDIConverter.convertModifications(new ModificationItem[0]);

    assertNotNull(sdkMods);

    assertEquals(sdkMods.length, 0);
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} array
   * of JNDI modification items to an array of SDK modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullSDKModifications()
         throws Exception
  {
    Modification[] sdkMods =
         JNDIConverter.convertModifications((ModificationItem[]) null);

    assertNotNull(sdkMods);

    assertEquals(sdkMods.length, 0);
  }



  /**
   * Provides test coverage for the method used to convert a non-empty array of
   * SDK modifications to an array of JNDI modification items.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDIModificationItems()
         throws Exception
  {
    ModificationItem[] jndiMods = JNDIConverter.convertModifications(
         new Modification(ModificationType.ADD, "a", "1"),
         new Modification(ModificationType.DELETE, "b", "2"),
         new Modification(ModificationType.REPLACE, "c", "3"));

    assertNotNull(jndiMods);

    assertEquals(jndiMods.length, 3);

    assertEquals(jndiMods[0].getModificationOp(), DirContext.ADD_ATTRIBUTE);
    assertEquals(jndiMods[0].getAttribute().getID(), "a");

    assertEquals(jndiMods[1].getModificationOp(), DirContext.REMOVE_ATTRIBUTE);
    assertEquals(jndiMods[1].getAttribute().getID(), "b");

    assertEquals(jndiMods[2].getModificationOp(), DirContext.REPLACE_ATTRIBUTE);
    assertEquals(jndiMods[2].getAttribute().getID(), "c");
  }



  /**
   * Provides test coverage for the method used to convert an empty array of
   * SDK modifications to an array of JNDI modification items.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToEmptyJNDIModificationItems()
         throws Exception
  {
    ModificationItem[] jndiMods =
         JNDIConverter.convertModifications(new Modification[0]);

    assertNotNull(jndiMods);

    assertEquals(jndiMods.length, 0);
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} array
   * of SDK modifications to an array of JNDI modification items.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullJNDIModificationItems()
         throws Exception
  {
    ModificationItem[] jndiMods =
         JNDIConverter.convertModifications((Modification[]) null);

    assertNotNull(jndiMods);

    assertEquals(jndiMods.length, 0);
  }



  /**
   * Provides test coverage for the method used to convert a JNDI search result
   * to an SDK entry with no context base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKEntryNoContextBaseDN()
         throws Exception
  {
    BasicAttributes jndiAttrs = new BasicAttributes();
    jndiAttrs.put(new BasicAttribute("dc", "example"));

    SearchResult searchResult =
         new SearchResult("dc=example,dc=com", null, jndiAttrs);

    Entry entry = JNDIConverter.convertSearchEntry(searchResult);

    assertNotNull(entry);

    assertEquals(entry.getParsedDN(), new DN("dc=example,dc=com"));

    assertEquals(entry.getAttributes().size(), 1);

    assertTrue(entry.hasAttributeValue("dc", "example"));
  }



  /**
   * Provides test coverage for the method used to convert a JNDI search result
   * to an SDK entry with an empty context base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKEntryNonEmptyNameEmptyContextBaseDN()
         throws Exception
  {
    BasicAttributes jndiAttrs = new BasicAttributes();
    jndiAttrs.put(new BasicAttribute("dc", "example"));

    SearchResult searchResult =
         new SearchResult("dc=example,dc=com", null, jndiAttrs);

    Entry entry = JNDIConverter.convertSearchEntry(searchResult, "");

    assertNotNull(entry);

    assertEquals(entry.getParsedDN(), new DN("dc=example,dc=com"));

    assertEquals(entry.getAttributes().size(), 1);

    assertTrue(entry.hasAttributeValue("dc", "example"));
  }



  /**
   * Provides test coverage for the method used to convert a JNDI search result
   * to an SDK entry with an empty context base DN and an empty name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKEntryEmptyNameEmptyContextBaseDN()
         throws Exception
  {
    BasicAttributes jndiAttrs = new BasicAttributes();
    jndiAttrs.put(new BasicAttribute("objectClass", "ds-root-dse"));

    SearchResult searchResult = new SearchResult("", null, jndiAttrs);

    Entry entry = JNDIConverter.convertSearchEntry(searchResult, "");

    assertNotNull(entry);

    assertEquals(entry.getParsedDN(), DN.NULL_DN);

    assertEquals(entry.getAttributes().size(), 1);

    assertTrue(entry.hasAttributeValue("objectClass", "ds-root-dse"));
  }



  /**
   * Provides test coverage for the method used to convert a JNDI search result
   * to an SDK entry with a non-empty name and a non-empty result name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKEntryNonEmptyNameNonEmptyContextBaseDN()
         throws Exception
  {
    BasicAttributes jndiAttrs = new BasicAttributes();
    jndiAttrs.put(new BasicAttribute("ou", "People"));

    SearchResult searchResult =
         new SearchResult("ou=People", null, jndiAttrs);

    Entry entry =
         JNDIConverter.convertSearchEntry(searchResult, "dc=example,dc=com");

    assertNotNull(entry);

    assertEquals(entry.getParsedDN(), new DN("ou=People,dc=example,dc=com"));

    assertEquals(entry.getAttributes().size(), 1);

    assertTrue(entry.hasAttributeValue("ou", "People"));
  }



  /**
   * Provides test coverage for the method used to convert a JNDI search result
   * to an SDK entry with a non-empty context base DN and an empty result name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToSDKEntryEmptyNameNonEmptyContextBaseDN()
         throws Exception
  {
    BasicAttributes jndiAttrs = new BasicAttributes();
    jndiAttrs.put(new BasicAttribute("dc", "example"));

    SearchResult searchResult =
         new SearchResult("", null, jndiAttrs);

    Entry entry =
         JNDIConverter.convertSearchEntry(searchResult, "dc=example,dc=com");

    assertNotNull(entry);

    assertEquals(entry.getParsedDN(), new DN("dc=example,dc=com"));

    assertEquals(entry.getAttributes().size(), 1);

    assertTrue(entry.hasAttributeValue("dc", "example"));
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} JNDI
   * search result to an SDK entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullSDKEntry()
         throws Exception
  {
    assertNull(JNDIConverter.convertSearchEntry((SearchResult) null));
  }



  /**
   * Provides test coverage for the method used to convert an SDK entry to a
   * JNDI search result with no context base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDISearchResultNoContextBaseDN()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: dc=example,dc=com",
         "dc: example");

    SearchResult searchResult = JNDIConverter.convertSearchEntry(entry);

    assertNotNull(searchResult);

    assertEquals(new DN(searchResult.getName()),
                 new DN("dc=example,dc=com"));

    assertEquals(searchResult.getAttributes().size(), 1);
  }



  /**
   * Provides test coverage for the method used to convert an SDK entry to a
   * JNDI search result with an empty context base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDISearchResultEmptyContextBaseDN()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: dc=example,dc=com",
         "dc: example");

    SearchResult searchResult = JNDIConverter.convertSearchEntry(entry, "");

    assertNotNull(searchResult);

    assertEquals(new DN(searchResult.getName()),
                 new DN("dc=example,dc=com"));

    assertEquals(searchResult.getAttributes().size(), 1);
  }



  /**
   * Provides test coverage for the method used to convert an SDK entry to a
   * JNDI search result with a context base DN that equals the full entry DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDISearchResultContextBaseDNEqualsEntryDN()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: dc=example,dc=com",
         "dc: example");

    SearchResult searchResult =
         JNDIConverter.convertSearchEntry(entry, "dc=example,dc=com");

    assertNotNull(searchResult);

    assertEquals(new DN(searchResult.getName()), DN.NULL_DN);

    assertEquals(searchResult.getAttributes().size(), 1);
  }



  /**
   * Provides test coverage for the method used to convert an SDK entry to a
   * JNDI search result with a context base DN that is superior to the entry DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDISearchResultContextBaseDNSuperiorToEntryDN()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: ou=People,dc=example,dc=com",
         "ou: People");

    SearchResult searchResult =
         JNDIConverter.convertSearchEntry(entry, "dc=example,dc=com");

    assertNotNull(searchResult);

    assertEquals(new DN(searchResult.getName()), new DN("ou=People"));

    assertEquals(searchResult.getAttributes().size(), 1);
  }



  /**
   * Provides test coverage for the method used to convert an SDK entry to a
   * JNDI search result with a context base DN that is not superior to the entry
   * DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDISearchResultContextBaseDNNotSuperiorToEntryDN()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: ou=People,dc=example,dc=com",
         "ou: People");

    SearchResult searchResult =
         JNDIConverter.convertSearchEntry(entry, "o=example.com");

    assertNotNull(searchResult);

    assertEquals(new DN(searchResult.getName()),
         new DN("ou=People,dc=example,dc=com"));

    assertEquals(searchResult.getAttributes().size(), 1);
  }



  /**
   * Provides test coverage for the method used to convert an SDK entry to a
   * JNDI search result with a context base DN that is not superior to the entry
   * DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJNDISearchResultContextMalformedBaseDN()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: ou=People,dc=example,dc=com",
         "ou: People");

    SearchResult searchResult =
         JNDIConverter.convertSearchEntry(entry, "malformed");

    assertNotNull(searchResult);

    assertEquals(new DN(searchResult.getName()),
         new DN("ou=People,dc=example,dc=com"));

    assertEquals(searchResult.getAttributes().size(), 1);
  }



  /**
   * Provides test coverage for the method used to convert a {@code null} SDK
   * entry to a JNDI search result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToNullJNDISearchResult()
         throws Exception
  {
    assertNull(JNDIConverter.convertSearchEntry((Entry) null));
  }
}
