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
package com.unboundid.ldap.sdk.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchResultEntry;



/**
 * This class provides a set of test cases for the
 * EntryChangeNotificationControl class.
 */
public class EntryChangeNotificationControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Test the first constructor.
   */
  @Test()
  public void testConstructor1()
  {
    new EntryChangeNotificationControl();
  }



  /**
   * Test the second constructor.
   */
  @Test()
  public void testConstructor2()
  {
    long changeNumber = 2L * Integer.MAX_VALUE;

    EntryChangeNotificationControl c =
         new EntryChangeNotificationControl(
                  PersistentSearchChangeType.MODIFY_DN,
                  "ou=People,dc=example,dc=com", changeNumber);

    assertEquals(c.getChangeType(), PersistentSearchChangeType.MODIFY_DN);

    assertNotNull(c.getPreviousDN());
    assertEquals(c.getPreviousDN(), "ou=People,dc=example,dc=com");

    assertEquals(c.getChangeNumber(), changeNumber);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Test the third constructor.
   */
  @Test()
  public void testConstructor3()
  {
    EntryChangeNotificationControl c =
         new EntryChangeNotificationControl(
                  PersistentSearchChangeType.MODIFY_DN,
                  "ou=People,dc=example,dc=com", 5, false);

    assertEquals(c.getChangeType(), PersistentSearchChangeType.MODIFY_DN);

    assertNotNull(c.getPreviousDN());
    assertEquals(c.getPreviousDN(), "ou=People,dc=example,dc=com");

    assertEquals(c.getChangeNumber(), 5);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor with a valid control with all elements
   * present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4AllElements()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Enumerated(PersistentSearchChangeType.MODIFY_DN.intValue()),
      new ASN1OctetString("ou=People,dc=example,dc=com"),
      new ASN1Integer(5)
    };

    EntryChangeNotificationControl c =
         new EntryChangeNotificationControl("2.16.840.1.113730.3.4.7", false,
                 new ASN1OctetString(new ASN1Sequence(elements).encode()));

    assertEquals(c.getChangeType().intValue(), 8);

    assertNotNull(c.getPreviousDN());
    assertEquals(c.getPreviousDN(), "ou=People,dc=example,dc=com");

    assertEquals(c.getChangeNumber(), 5);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor with a valid control with a minimal set of
   * elements present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4MinimalElements()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Enumerated(PersistentSearchChangeType.ADD.intValue()),
    };

    EntryChangeNotificationControl c =
         new EntryChangeNotificationControl("2.16.840.1.113730.3.4.7", false,
                 new ASN1OctetString(new ASN1Sequence(elements).encode()));

    assertEquals(c.getChangeType().intValue(), 1);

    assertNull(c.getPreviousDN());

    assertEquals(c.getChangeNumber(), -1);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor with a valid control with a {@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor4NullValue()
         throws Exception
  {
     new EntryChangeNotificationControl("2.16.840.1.113730.3.4.7", false, null);
  }



  /**
   * Tests the fourth constructor with a valid control with a value that can't
   * be decoded as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor4ValueNotSequence()
         throws Exception
  {
     new EntryChangeNotificationControl("2.16.840.1.113730.3.4.7", false,
              new ASN1OctetString(new ASN1Integer(5).encode()));
  }



  /**
   * Tests the fourth constructor with a valid control with a value sequence
   * with an invalid number of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor4InvalidValueSequenceElementCount()
         throws Exception
  {
     new EntryChangeNotificationControl("2.16.840.1.113730.3.4.7", false,
              new ASN1OctetString(new ASN1Sequence().encode()));
  }



  /**
   * Tests the fourth constructor with a valid control with a value sequence
   * with a change type that is not an enumerated element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor4ChangeTypeNotEnumerated()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString()
    };

     new EntryChangeNotificationControl("2.16.840.1.113730.3.4.7", false,
              new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the fourth constructor with a valid control with a value sequence
   * with an invalid change type value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor4InvalidChangeType()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Enumerated(0)
    };

     new EntryChangeNotificationControl("2.16.840.1.113730.3.4.7", false,
              new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the fourth constructor with a valid control with a value sequence
   * with a second element that does not have an acceptable type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor4InvalidExtraElementType()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Enumerated(1),
      new ASN1Sequence()
    };

     new EntryChangeNotificationControl("2.16.840.1.113730.3.4.7", false,
              new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the fourth constructor with a valid control with a value sequence
   * with a second element with an integer type but a value that can't be
   * decoded as an integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor4CannotDecodeChangeType()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Enumerated(1),
      new ASN1OctetString((byte) 0x02)
    };

     new EntryChangeNotificationControl("2.16.840.1.113730.3.4.7", false,
              new ASN1OctetString(new ASN1Sequence(elements).encode()));
  }



  /**
   * Tests the {@code get} method with an entry that does not contain an entry
   * change notification control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final EntryChangeNotificationControl c =
         EntryChangeNotificationControl.get(e);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with an entry that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidCorrectType()
         throws Exception
  {
    final Control[] controls =
    {
      new EntryChangeNotificationControl(PersistentSearchChangeType.ADD, null,
           1L)
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final EntryChangeNotificationControl c =
         EntryChangeNotificationControl.get(e);
    assertNotNull(c);

    assertEquals(c.getChangeType(), PersistentSearchChangeType.ADD);

    assertNull(c.getPreviousDN());

    assertEquals(c.getChangeNumber(), 1L);
  }



  /**
   * Tests the {@code get} method with an entry that contains a response control
   * that is a generic control that can be parsed as an entry change
   * notification control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp = new EntryChangeNotificationControl(
         PersistentSearchChangeType.ADD, null, 1L);

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final EntryChangeNotificationControl c =
         EntryChangeNotificationControl.get(e);
    assertNotNull(c);

    assertEquals(c.getChangeType(), PersistentSearchChangeType.ADD);

    assertNull(c.getPreviousDN());

    assertEquals(c.getChangeNumber(), 1L);
  }



  /**
   * Tests the {@code get} method with an entry that contains a response control
   * that is a generic control that cannot be parsed as an entry change
   * notification control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(EntryChangeNotificationControl.ENTRY_CHANGE_NOTIFICATION_OID,
           false, null)
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    EntryChangeNotificationControl.get(e);
  }
}
