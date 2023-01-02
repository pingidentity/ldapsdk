/*
 * Copyright 2017-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2023 Ping Identity Corporation
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
 * Copyright (C) 2017-2023 Ping Identity Corporation
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



import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



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



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the control includes unique attributes and no
   * filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithAttributesWithoutFilter()
          throws Exception
  {
    final String uniquenessID = UUID.randomUUID().toString();

    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, uniquenessID, properties);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("uniqueness-id", uniquenessID),
              new JSONField("attribute-types", new JSONArray(
                   new JSONString("uid"))),
              new JSONField("prevent-conflicts-with-soft-deleted-entries",
                   false),
              new JSONField("pre-commit-validation-level",
                   "all-available-backend-servers"),
              new JSONField("post-commit-validation-level", "all-backend-sets"),
              new JSONField("alert-on-post-commit-conflict-detection", true),
              new JSONField("create-conflict-prevention-details-entry",
                   false)));


    UniquenessRequestControl decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), uniquenessID);

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("uid"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());


    decodedControl =
         (UniquenessRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), uniquenessID);

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("uid"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the control includes a filter and no unique
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithoutAttributesWithFilter()
          throws Exception
  {
    final String uniquenessID = UUID.randomUUID().toString();

    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties(
              Filter.createEqualityFilter("uid", "jdoe"));
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, uniquenessID, properties);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("uniqueness-id", uniquenessID),
              new JSONField("filter", "(uid=jdoe)"),
              new JSONField("prevent-conflicts-with-soft-deleted-entries",
                   false),
              new JSONField("pre-commit-validation-level",
                   "all-available-backend-servers"),
              new JSONField("post-commit-validation-level", "all-backend-sets"),
              new JSONField("alert-on-post-commit-conflict-detection", true),
              new JSONField("create-conflict-prevention-details-entry",
                   false)));


    UniquenessRequestControl decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), uniquenessID);

    assertTrue(decodedControl.getAttributeTypes().isEmpty());

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertEquals(decodedControl.getFilter(),
         Filter.createEqualityFilter("uid", "jdoe"));

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());


    decodedControl =
         (UniquenessRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), uniquenessID);

    assertTrue(decodedControl.getAttributeTypes().isEmpty());

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertEquals(decodedControl.getFilter(),
         Filter.createEqualityFilter("uid", "jdoe"));

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the control includes both unique attributes and a
   * filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlWithAttributesWithFilter()
          throws Exception
  {
    final String uniquenessID = UUID.randomUUID().toString();

    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("givenName", "sn");
    properties.setMultipleAttributeBehavior(
         UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);
    properties.setFilter(Filter.createEqualityFilter("uid", "jdoe"));
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, uniquenessID, properties);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("uniqueness-id", uniquenessID),
              new JSONField("attribute-types", new JSONArray(
                   new JSONString("givenName"),
                   new JSONString("sn"))),
              new JSONField("multiple-attribute-behavior",
                   "unique-in-combination"),
              new JSONField("filter", "(uid=jdoe)"),
              new JSONField("prevent-conflicts-with-soft-deleted-entries",
                   false),
              new JSONField("pre-commit-validation-level",
                   "all-available-backend-servers"),
              new JSONField("post-commit-validation-level", "all-backend-sets"),
              new JSONField("alert-on-post-commit-conflict-detection", true),
              new JSONField("create-conflict-prevention-details-entry",
                   false)));


    UniquenessRequestControl decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), uniquenessID);

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("givenName", "sn"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);

    assertNull(decodedControl.getBaseDN());

    assertEquals(decodedControl.getFilter(),
         Filter.createEqualityFilter("uid", "jdoe"));

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());


    decodedControl =
         (UniquenessRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), uniquenessID);

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("givenName", "sn"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);

    assertNull(decodedControl.getBaseDN());

    assertEquals(decodedControl.getFilter(),
         Filter.createEqualityFilter("uid", "jdoe"));

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object with all field set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAllFieldsSet()
          throws Exception
  {
    final String uniquenessID = UUID.randomUUID().toString();

    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("givenName", "sn");
    properties.setMultipleAttributeBehavior(
         UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);
    properties.setBaseDN("dc=example,dc=com");
    properties.setFilter(Filter.createEqualityFilter("uid", "jdoe"));
    properties.setPreventConflictsWithSoftDeletedEntries(true);
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_BACKEND_SETS);
    properties.setAlertOnPostCommitConflictDetection(false);
    properties.setCreateConflictPreventionDetailsEntry(true);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, uniquenessID, properties);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("uniqueness-id", uniquenessID),
              new JSONField("attribute-types", new JSONArray(
                   new JSONString("givenName"),
                   new JSONString("sn"))),
              new JSONField("multiple-attribute-behavior",
                   "unique-in-combination"),
              new JSONField("base-dn", "dc=example,dc=com"),
              new JSONField("filter", "(uid=jdoe)"),
              new JSONField("prevent-conflicts-with-soft-deleted-entries",
                   true),
              new JSONField("pre-commit-validation-level",
                   "all-available-backend-servers"),
              new JSONField("post-commit-validation-level", "all-backend-sets"),
              new JSONField("alert-on-post-commit-conflict-detection", false),
              new JSONField("create-conflict-prevention-details-entry",
                   true)));


    UniquenessRequestControl decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), uniquenessID);

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("givenName", "sn"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);

    assertEquals(decodedControl.getBaseDN(), "dc=example,dc=com");

    assertEquals(decodedControl.getFilter(),
         Filter.createEqualityFilter("uid", "jdoe"));

    assertTrue(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertFalse(decodedControl.alertOnPostCommitConflictDetection());

    assertTrue(decodedControl.createConflictPreventionDetailsEntry());


    decodedControl =
         (UniquenessRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), uniquenessID);

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("givenName", "sn"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);

    assertEquals(decodedControl.getBaseDN(), "dc=example,dc=com");

    assertEquals(decodedControl.getFilter(),
         Filter.createEqualityFilter("uid", "jdoe"));

    assertTrue(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertFalse(decodedControl.alertOnPostCommitConflictDetection());

    assertTrue(decodedControl.createConflictPreventionDetailsEntry());
  }



  /**
   * Tests the behavior when trying to encode and decode the control with a
   * variety of multiple attribute behaviors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleAttributeBehaviors()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("givenName", "sn");
    properties.setMultipleAttributeBehavior(
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    JSONObject controlObject = c.toJSONControl();
    assertNotNull(controlObject);

    UniquenessRequestControl decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNotNull(decodedControl.getUniquenessID());

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("givenName", "sn"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());


    properties.setMultipleAttributeBehavior(
         UniquenessMultipleAttributeBehavior.
              UNIQUE_ACROSS_ALL_ATTRIBUTES_INCLUDING_IN_SAME_ENTRY);

    c = new UniquenessRequestControl(true, null, properties);

    controlObject = c.toJSONControl();
    assertNotNull(controlObject);

    decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNotNull(decodedControl.getUniquenessID());

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("givenName", "sn"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.
              UNIQUE_ACROSS_ALL_ATTRIBUTES_INCLUDING_IN_SAME_ENTRY);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());


    properties.setMultipleAttributeBehavior(
         UniquenessMultipleAttributeBehavior.
              UNIQUE_ACROSS_ALL_ATTRIBUTES_EXCEPT_IN_SAME_ENTRY);

    c = new UniquenessRequestControl(true, null, properties);

    controlObject = c.toJSONControl();
    assertNotNull(controlObject);

    decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNotNull(decodedControl.getUniquenessID());

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("givenName", "sn"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.
              UNIQUE_ACROSS_ALL_ATTRIBUTES_EXCEPT_IN_SAME_ENTRY);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());


    properties.setMultipleAttributeBehavior(
         UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);

    c = new UniquenessRequestControl(true, null, properties);

    controlObject = c.toJSONControl();
    assertNotNull(controlObject);

    decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNotNull(decodedControl.getUniquenessID());

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("givenName", "sn"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());
  }



  /**
   * Tests the behavior when trying to encode and decode the control with a
   * variety of validation levels.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidationLevels()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.NONE);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    JSONObject controlObject = c.toJSONControl();
    assertNotNull(controlObject);

    UniquenessRequestControl decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNotNull(decodedControl.getUniquenessID());

    assertEquals(decodedControl.getAttributeTypes(), StaticUtils.setOf("uid"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.NONE);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());


    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_BACKEND_SETS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    c = new UniquenessRequestControl(true, null, properties);

    controlObject = c.toJSONControl();
    assertNotNull(controlObject);

    decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNotNull(decodedControl.getUniquenessID());

    assertEquals(decodedControl.getAttributeTypes(), StaticUtils.setOf("uid"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final String uniquenessID = UUID.randomUUID().toString();

    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, uniquenessID, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    UniquenessRequestControl decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), uniquenessID);

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("uid"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());


    decodedControl =
         (UniquenessRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), uniquenessID);

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("uid"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value contains the minimum set of fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlMinimalFields()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attribute-types", new JSONArray(
                   new JSONString("uid"))),
              new JSONField("pre-commit-validation-level",
                   "all-subtree-views"),
              new JSONField("post-commit-validation-level",
                   "all-subtree-views"))));


    UniquenessRequestControl decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNotNull(decodedControl.getUniquenessID());

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("uid"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());


    decodedControl =
         (UniquenessRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNotNull(decodedControl.getUniquenessID());

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("uid"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value does not contain either attribute types or a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlWithoutAttributeTypesOrFilter()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("pre-commit-validation-level",
                   "all-subtree-views"),
              new JSONField("post-commit-validation-level",
                   "all-subtree-views"))));

    UniquenessRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is has an attribute type value that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlAttributeTypeNotString()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attribute-types", new JSONArray(
                   new JSONNumber(1234))),
              new JSONField("pre-commit-validation-level",
                   "all-subtree-views"),
              new JSONField("post-commit-validation-level",
                   "all-subtree-views"))));

    UniquenessRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized multiple-attribute-behavior value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlUnrecognizedMultipleAttributeBehavior()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attribute-types", new JSONArray(
                   new JSONString("uid"))),
              new JSONField("multiple-attribute-behavior", "unrecognized"),
              new JSONField("pre-commit-validation-level",
                   "all-subtree-views"),
              new JSONField("post-commit-validation-level",
                   "all-subtree-views"))));

    UniquenessRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an invalid filter value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlInvalidFilter()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attribute-types", new JSONArray(
                   new JSONString("uid"))),
              new JSONField("filter", "invalid"),
              new JSONField("pre-commit-validation-level",
                   "all-subtree-views"),
              new JSONField("post-commit-validation-level",
                   "all-subtree-views"))));

    UniquenessRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the pre-commit-validation-level field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlMissingPreCommitValidationLevel()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attribute-types", new JSONArray(
                   new JSONString("uid"))),
              new JSONField("post-commit-validation-level",
                   "all-subtree-views"))));

    UniquenessRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is has an invalid pre-commit-validation-level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlInvalidPreCommitValidationLevel()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attribute-types", new JSONArray(
                   new JSONString("uid"))),
              new JSONField("pre-commit-validation-level",
                   "invalid"),
              new JSONField("post-commit-validation-level",
                   "all-subtree-views"))));

    UniquenessRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the post-commit-validation-level field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlMissingPostCommitValidationLevel()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attribute-types", new JSONArray(
                   new JSONString("uid"))),
              new JSONField("pre-commit-validation-level",
                   "all-subtree-views"))));

    UniquenessRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is has an invalid post-commit-validation-level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlInvalidPostCommitValidationLevel()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attribute-types", new JSONArray(
                   new JSONString("uid"))),
              new JSONField("pre-commit-validation-level",
                   "all-subtree-views"),
              new JSONField("post-commit-validation-level",
                   "invalid"))));

    UniquenessRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlUnrecognizedFieldStrict()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attribute-types", new JSONArray(
                   new JSONString("uid"))),
              new JSONField("pre-commit-validation-level",
                   "all-subtree-views"),
              new JSONField("post-commit-validation-level",
                   "all-subtree-views"),
              new JSONField("unrecognized", "foo"))));

    UniquenessRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlUnrecognizedFieldNonStrict()
          throws Exception
  {
    final UniquenessRequestControlProperties properties =
         new UniquenessRequestControlProperties("uid");
    properties.setPreCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);
    properties.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    final UniquenessRequestControl c =
         new UniquenessRequestControl(true, null, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("attribute-types", new JSONArray(
                   new JSONString("uid"))),
              new JSONField("pre-commit-validation-level",
                   "all-subtree-views"),
              new JSONField("post-commit-validation-level",
                   "all-subtree-views"),
              new JSONField("unrecognized", "foo"))));


    UniquenessRequestControl decodedControl =
         UniquenessRequestControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNotNull(decodedControl.getUniquenessID());

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("uid"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());


    decodedControl =
         (UniquenessRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertNotNull(decodedControl.getUniquenessID());

    assertEquals(decodedControl.getAttributeTypes(),
         StaticUtils.setOf("uid"));

    assertEquals(decodedControl.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(decodedControl.getBaseDN());

    assertNull(decodedControl.getFilter());

    assertFalse(decodedControl.preventConflictsWithSoftDeletedEntries());

    assertEquals(decodedControl.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertEquals(decodedControl.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(decodedControl.alertOnPostCommitConflictDetection());

    assertFalse(decodedControl.createConflictPreventionDetailsEntry());
  }
}
