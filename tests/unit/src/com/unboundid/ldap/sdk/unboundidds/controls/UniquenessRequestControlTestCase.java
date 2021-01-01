/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the uniqueness request control
 * class.
 */
public final class UniquenessRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a control created from a set of properties with a
   * single attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithSingleAttributeType()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties("uid");

    UniquenessRequestControl c =
         new UniquenessRequestControl(true, "uniqueness-id", p);
    c = new UniquenessRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.52");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getUniquenessID());
    assertEquals(c.getUniquenessID(), "uniqueness-id");

    assertNotNull(c.getAttributeTypes());
    assertFalse(c.getAttributeTypes().isEmpty());
    assertEquals(c.getAttributeTypes().size(), 1);
    assertTrue(c.getAttributeTypes().contains("uid"));

    assertNotNull(c.getMultipleAttributeBehavior());
    assertEquals(c.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(c.getBaseDN());

    assertNull(c.getFilter());

    assertFalse(c.preventConflictsWithSoftDeletedEntries());

    assertNotNull(c.getPreCommitValidationLevel());
    assertEquals(c.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(c.getPostCommitValidationLevel());
    assertEquals(c.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(c.alertOnPostCommitConflictDetection());

    assertFalse(c.createConflictPreventionDetailsEntry());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control created from a set of properties with
   * multiple attribute types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithMultipleAttributeTypes()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties("mail", "mailAlternateAddress");

    UniquenessRequestControl c = new UniquenessRequestControl(false, null, p);
    c = new UniquenessRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.52");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getUniquenessID());

    assertNotNull(c.getAttributeTypes());
    assertFalse(c.getAttributeTypes().isEmpty());
    assertEquals(c.getAttributeTypes().size(), 2);
    assertTrue(c.getAttributeTypes().contains("mail"));
    assertTrue(c.getAttributeTypes().contains("mailAlternateAddress"));

    assertNotNull(c.getMultipleAttributeBehavior());
    assertEquals(c.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(c.getBaseDN());

    assertNull(c.getFilter());

    assertFalse(c.preventConflictsWithSoftDeletedEntries());

    assertNotNull(c.getPreCommitValidationLevel());
    assertEquals(c.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(c.getPostCommitValidationLevel());
    assertEquals(c.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(c.alertOnPostCommitConflictDetection());

    assertFalse(c.createConflictPreventionDetailsEntry());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control created from a set of properties with a
   * filter rather than a set of attribute types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithFilter()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties(
              Filter.createEqualityFilter("uid", "john.doe"));

    UniquenessRequestControl c = new UniquenessRequestControl(true, null, p);
    c = new UniquenessRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.52");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getUniquenessID());

    assertNotNull(c.getAttributeTypes());
    assertTrue(c.getAttributeTypes().isEmpty());

    assertNotNull(c.getMultipleAttributeBehavior());
    assertEquals(c.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(c.getBaseDN());

    assertNotNull(c.getFilter());
    assertEquals(c.getFilter(),
         Filter.createEqualityFilter("uid", "john.doe"));

    assertFalse(c.preventConflictsWithSoftDeletedEntries());

    assertNotNull(c.getPreCommitValidationLevel());
    assertEquals(c.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(c.getPostCommitValidationLevel());
    assertEquals(c.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(c.alertOnPostCommitConflictDetection());

    assertFalse(c.createConflictPreventionDetailsEntry());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control created from set of properties with
   * multiple attribute types, and with all properties set to non-default
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllPropertiesSetToNonDefaultValues()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties("mail", "mailAlternateAddress");
    p.setMultipleAttributeBehavior(
         UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);
    p.setBaseDN("dc=example,dc=com");
    p.setFilter(Filter.createEqualityFilter("foo", "bar"));
    p.setPreventConflictsWithSoftDeletedEntries(true);
    p.setPreCommitValidationLevel(UniquenessValidationLevel.ALL_BACKEND_SETS);
    p.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);
    p.setAlertOnPostCommitConflictDetection(false);
    p.setCreateConflictPreventionDetailsEntry(true);

    UniquenessRequestControl c =
         new UniquenessRequestControl(true, "uniqueness-id", p);
    c = new UniquenessRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.52");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getUniquenessID());
    assertEquals(c.getUniquenessID(), "uniqueness-id");

    assertNotNull(c.getAttributeTypes());
    assertFalse(c.getAttributeTypes().isEmpty());
    assertEquals(c.getAttributeTypes().size(), 2);
    assertTrue(c.getAttributeTypes().contains("mail"));
    assertTrue(c.getAttributeTypes().contains("mailAlternateAddress"));

    assertNotNull(c.getMultipleAttributeBehavior());
    assertEquals(c.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);

    assertNotNull(c.getBaseDN());
    assertEquals(c.getBaseDN(), "dc=example,dc=com");

    assertNotNull(c.getFilter());
    assertEquals(c.getFilter(), Filter.createEqualityFilter("foo", "bar"));

    assertTrue(c.preventConflictsWithSoftDeletedEntries());

    assertNotNull(c.getPreCommitValidationLevel());
    assertEquals(c.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertNotNull(c.getPostCommitValidationLevel());
    assertEquals(c.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertFalse(c.alertOnPostCommitConflictDetection());

    assertTrue(c.createConflictPreventionDetailsEntry());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to create a uniqueness request control
   * without either a set of attribute types or a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCreateWithoutAttributeTypesOrFilter()
         throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setAttributeTypes();
    new UniquenessRequestControl(true, null, properties);
  }



  /**
   * Tests the behavior when trying to decode a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithoutValue()
         throws Exception
  {
    new UniquenessRequestControl(new Control("1.3.6.1.4.1.30221.2.5.52", true));
  }



  /**
   * Tests the behavior when trying to decode a control whose value cannot be
   * parsed as a BER sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotSequence()
         throws Exception
  {
    new UniquenessRequestControl(new Control("1.3.6.1.4.1.30221.2.5.52", true,
         new ASN1OctetString("malformed")));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence has
   * an invalid multiple attribute behavior value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceInvalidMultipleAttributeBehavior()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "uniqueness-id"),
         new ASN1Set((byte) 0xA1, new ASN1OctetString("uid")),
         new ASN1Enumerated((byte) 0x82, 12345));

    new UniquenessRequestControl(new Control("1.3.6.1.4.1.30221.2.5.52", true,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence has
   * an invalid multiple pre-commit validation level value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceInvalidPreCommitValidationLevel()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "uniqueness-id"),
         new ASN1Set((byte) 0xA1, new ASN1OctetString("uid")),
         new ASN1Enumerated((byte) 0x86, 12345));

    new UniquenessRequestControl(new Control("1.3.6.1.4.1.30221.2.5.52", true,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence has
   * an invalid multiple post-commit validation level value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceInvalidPostCommitValidationLevel()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "uniqueness-id"),
         new ASN1Set((byte) 0xA1, new ASN1OctetString("uid")),
         new ASN1Enumerated((byte) 0x87, 12345));

    new UniquenessRequestControl(new Control("1.3.6.1.4.1.30221.2.5.52", true,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence has
   * an element with an unrecognized BER type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceUnrecognizedElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "uniqueness-id"),
         new ASN1Set((byte) 0xA1, new ASN1OctetString("uid")),
         new ASN1Enumerated((byte) 0x8F, 12345));

    new UniquenessRequestControl(new Control("1.3.6.1.4.1.30221.2.5.52", true,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence is
   * missing the required uniqueness ID element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceMissingUniquenessID()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Set((byte) 0xA1, new ASN1OctetString("uid")));

    new UniquenessRequestControl(new Control("1.3.6.1.4.1.30221.2.5.52", true,
         new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * does not have either a set of attribute types or a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceNeitherAttributesNorFilter()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "uniqueness-id"));

    new UniquenessRequestControl(new Control("1.3.6.1.4.1.30221.2.5.52", true,
         new ASN1OctetString(valueSequence.encode())));
  }
}
