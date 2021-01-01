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
package com.unboundid.ldif;



import java.util.Arrays;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IgnoreNoUserModificationRequestControl;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the LDIFAddChangeRecord class.
 */
public class LDIFAddChangeRecordTestCase
       extends LDIFTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    LDIFAddChangeRecord r = new LDIFAddChangeRecord("dc=example,dc=com", attrs);

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getAttributes());
    assertEquals(r.getAttributes().length, 2);

    AddRequest addRequest = r.toAddRequest();
    assertNotNull(addRequest);
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.ADD);

    String[] ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

    r.hashCode();

    ByteStringBuffer byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertNotNull(byteBuffer.toString());

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertNotNull(byteBuffer.toString());

    StringBuilder stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertNotNull(r.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertNotNull(r.toString());

    assertNotNull(r.toLDIFString());
    assertNotNull(r.toLDIFString(10));
    assertNotNull(r.toString());

    assertNotNull(r.getEntryToAdd());
    assertEquals(r.getEntryToAdd(),
         new Entry(r.getDN(), r.getAttributes()));

    assertNotNull(r.getControls());
    assertTrue(r.getControls().isEmpty());


    r = r.duplicate();

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getAttributes());
    assertEquals(r.getAttributes().length, 2);

    addRequest = r.toAddRequest();
    assertNotNull(addRequest);
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.ADD);

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

    r.hashCode();

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertNotNull(byteBuffer.toString());

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertNotNull(byteBuffer.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertNotNull(r.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertNotNull(r.toString());

    assertNotNull(r.toLDIFString());
    assertNotNull(r.toLDIFString(10));
    assertNotNull(r.toString());

    assertNotNull(r.getEntryToAdd());
    assertEquals(r.getEntryToAdd(),
         new Entry(r.getDN(), r.getAttributes()));

    assertNotNull(r.getControls());
    assertTrue(r.getControls().isEmpty());


    r = r.duplicate((Control[]) null);

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getAttributes());
    assertEquals(r.getAttributes().length, 2);

    addRequest = r.toAddRequest();
    assertNotNull(addRequest);
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.ADD);

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

    r.hashCode();

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertNotNull(byteBuffer.toString());

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertNotNull(byteBuffer.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertNotNull(r.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertNotNull(r.toString());

    assertNotNull(r.toLDIFString());
    assertNotNull(r.toLDIFString(10));
    assertNotNull(r.toString());

    assertNotNull(r.getEntryToAdd());
    assertEquals(r.getEntryToAdd(),
         new Entry(r.getDN(), r.getAttributes()));

    assertNotNull(r.getControls());
    assertTrue(r.getControls().isEmpty());


    r = r.duplicate(new Control[0]);

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getAttributes());
    assertEquals(r.getAttributes().length, 2);

    addRequest = r.toAddRequest();
    assertNotNull(addRequest);
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.ADD);

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

    r.hashCode();

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertNotNull(byteBuffer.toString());

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertNotNull(byteBuffer.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertNotNull(r.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertNotNull(r.toString());

    assertNotNull(r.toLDIFString());
    assertNotNull(r.toLDIFString(10));
    assertNotNull(r.toString());

    assertNotNull(r.getEntryToAdd());
    assertEquals(r.getEntryToAdd(),
         new Entry(r.getDN(), r.getAttributes()));

    assertNotNull(r.getControls());
    assertTrue(r.getControls().isEmpty());


    r = r.duplicate(new ManageDsaITRequestControl(false));

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getAttributes());
    assertEquals(r.getAttributes().length, 2);

    addRequest = r.toAddRequest();
    assertNotNull(addRequest);
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.ADD);

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 6);

    r.hashCode();

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertNotNull(byteBuffer.toString());

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertNotNull(byteBuffer.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertNotNull(r.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertNotNull(r.toString());

    assertNotNull(r.toLDIFString());
    assertNotNull(r.toLDIFString(10));
    assertNotNull(r.toString());

    assertNotNull(r.getEntryToAdd());
    assertEquals(r.getEntryToAdd(),
         new Entry(r.getDN(), r.getAttributes()));

    assertNotNull(r.getControls());
    assertFalse(r.getControls().isEmpty());
    assertEquals(r.getControls(),
         Collections.singletonList(new ManageDsaITRequestControl(false)));


    r = r.duplicate(new ManageDsaITRequestControl(false),
         new IgnoreNoUserModificationRequestControl(false));

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getAttributes());
    assertEquals(r.getAttributes().length, 2);

    addRequest = r.toAddRequest();
    assertNotNull(addRequest);
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.ADD);

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 7);

    r.hashCode();

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertNotNull(byteBuffer.toString());

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertNotNull(byteBuffer.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertNotNull(r.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertNotNull(r.toString());

    assertNotNull(r.toLDIFString());
    assertNotNull(r.toLDIFString(10));
    assertNotNull(r.toString());

    assertNotNull(r.getEntryToAdd());
    assertEquals(r.getEntryToAdd(),
         new Entry(r.getDN(), r.getAttributes()));

    assertNotNull(r.getControls());
    assertFalse(r.getControls().isEmpty());
    assertEquals(r.getControls(),
         Arrays.asList(new ManageDsaITRequestControl(false),
              new IgnoreNoUserModificationRequestControl(false)));
  }



  /**
   * Tests the first constructor with a {@code null} DN.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullDN()
  {
    Attribute[] attrs =
    {
      new Attribute("objectClass", "top", "domain"),
      new Attribute("dc", "example")
    };

    new LDIFAddChangeRecord(null, attrs);
  }



  /**
   * Tests the first constructor with a {@code null} set of attributes.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullAttrs()
  {
    new LDIFAddChangeRecord("dc=example,dc=com", (Attribute[]) null);
  }



  /**
   * Tests the first constructor with an empty set of attributes.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1EmptyAttrs()
  {
    new LDIFAddChangeRecord("dc=example,dc=com");
  }



  /**
   * Tests the second constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    Entry e = new Entry("dn: dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: domain",
                        "dc: example");

    LDIFAddChangeRecord r = new LDIFAddChangeRecord(e);

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getAttributes());
    assertEquals(r.getAttributes().length, 2);

    AddRequest addRequest = r.toAddRequest();
    assertNotNull(addRequest);
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.ADD);

    String[] ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

    r.hashCode();

    ByteStringBuffer byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertNotNull(byteBuffer.toString());

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertNotNull(byteBuffer.toString());

    StringBuilder stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertNotNull(r.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertNotNull(r.toString());

    assertNotNull(r.toLDIFString());
    assertNotNull(r.toLDIFString(10));
    assertNotNull(r.toString());

    assertNotNull(r.getEntryToAdd());
    assertEquals(r.getEntryToAdd(),
         new Entry(r.getDN(), r.getAttributes()));
  }



  /**
   * Tests the second constructor with a {@code null} entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class,
                               NullPointerException.class })
  public void testConstructor2NullEntry()
         throws Exception
  {
    new LDIFAddChangeRecord((Entry) null);
  }



  /**
   * Tests the third constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    Entry e = new Entry("dn: dc=example,dc=com",
                        "objectClass: top",
                        "objectClass: domain",
                        "dc: example");

    LDIFAddChangeRecord r = new LDIFAddChangeRecord(new AddRequest(e));

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getAttributes());
    assertEquals(r.getAttributes().length, 2);

    AddRequest addRequest = r.toAddRequest();
    assertNotNull(addRequest);
    assertEquals(addRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.ADD);

    String[] ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

    r.hashCode();

    ByteStringBuffer byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer);
    assertNotNull(byteBuffer.toString());

    byteBuffer = new ByteStringBuffer();
    r.toLDIF(byteBuffer, 10);
    assertNotNull(byteBuffer.toString());

    StringBuilder stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer);
    assertNotNull(r.toString());

    stringBuffer = new StringBuilder();
    r.toLDIFString(stringBuffer, 10);
    assertNotNull(r.toString());

    assertNotNull(r.toLDIFString());
    assertNotNull(r.toLDIFString(10));
    assertNotNull(r.toString());

    assertNotNull(r.getEntryToAdd());
    assertEquals(r.getEntryToAdd(),
         new Entry(r.getDN(), r.getAttributes()));
  }



  /**
   * Tests the third constructor with a {@code null} add request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class,
                               NullPointerException.class })
  public void testConstructor3NullAddRequest()
         throws Exception
  {
    new LDIFAddChangeRecord((AddRequest) null);
  }



  /**
   * Tests the {@code hashCode} method for a change record with an invalid DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashCodeInvalidDN()
         throws Exception
  {
    LDIFAddChangeRecord r = new LDIFAddChangeRecord(new Entry(
         "dn: invalid",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    r.hashCode();
  }



  /**
   * Tests the {@code equals} method with a {@code null} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    LDIFAddChangeRecord r = new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    assertFalse(r.equals(null));
  }



  /**
   * Tests the {@code equals} method with the same object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    LDIFAddChangeRecord r = new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    assertTrue(r.equals(r));
  }



  /**
   * Tests the {@code equals} method with an equivalent change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalent()
         throws Exception
  {
    LDIFAddChangeRecord r1 = new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    LDIFAddChangeRecord r2 = new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    assertTrue(r1.equals(r2));
  }



  /**
   * Tests the {@code equals} method with an equivalent change record but with
   * attributes in a different order.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalentDifferentOrder()
         throws Exception
  {
    LDIFAddChangeRecord r1 = new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    LDIFAddChangeRecord r2 = new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "dc: example",
         "objectClass: domain",
         "objectClass: top"));

    assertTrue(r1.equals(r2));
  }



  /**
   * Tests the {@code equals} method with an object other than a change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotChangeRecord()
         throws Exception
  {
    LDIFAddChangeRecord r = new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    assertFalse(r.equals("not a change record"));
  }



  /**
   * Tests the {@code equals} method with an object that is a change record but
   * not an add change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotAddChangeRecord()
         throws Exception
  {
    LDIFAddChangeRecord r1 = new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    LDIFDeleteChangeRecord r2 = new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertFalse(r1.equals(r2));
  }
}
