/*
 * Copyright 2017-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2022 Ping Identity Corporation
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
 * Copyright (C) 2017-2022 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the uniqueness response control
 * class.
 */
public final class UniquenessResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a control created with just a uniqueness ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithJustUniquenessID()
         throws Exception
  {
    UniquenessResponseControl c = new UniquenessResponseControl(
         "uniqueness-id", null, null, null);

    c = new UniquenessResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.53");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertFalse(c.uniquenessConflictFound());

    assertNotNull(c.getUniquenessID());
    assertEquals(c.getUniquenessID(), "uniqueness-id");

    assertNotNull(c.getPreCommitValidationResult());
    assertEquals(c.getPreCommitValidationResult(),
         UniquenessValidationResult.VALIDATION_NOT_ATTEMPTED);

    assertNull(c.getPreCommitValidationPassed());

    assertNotNull(c.getPostCommitValidationResult());
    assertEquals(c.getPostCommitValidationResult(),
         UniquenessValidationResult.VALIDATION_NOT_ATTEMPTED);

    assertNull(c.getPostCommitValidationPassed());

    assertNull(c.getValidationMessage());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control created with all elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithAllElements()
         throws Exception
  {
    UniquenessResponseControl c = new UniquenessResponseControl(
         "another-uniqueness-id", true, false, "validation message");

    c = new UniquenessResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.53");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertTrue(c.uniquenessConflictFound());

    assertNotNull(c.getUniquenessID());
    assertEquals(c.getUniquenessID(), "another-uniqueness-id");

    assertNotNull(c.getPreCommitValidationResult());
    assertEquals(c.getPreCommitValidationResult(),
         UniquenessValidationResult.VALIDATION_PASSED);

    assertNotNull(c.getPreCommitValidationPassed());
    assertEquals(c.getPreCommitValidationPassed(), Boolean.TRUE);

    assertNotNull(c.getPostCommitValidationResult());
    assertEquals(c.getPostCommitValidationResult(),
         UniquenessValidationResult.VALIDATION_FAILED);

    assertNotNull(c.getPostCommitValidationPassed());
    assertEquals(c.getPostCommitValidationPassed(), Boolean.FALSE);

    assertNotNull(c.getValidationMessage());
    assertEquals(c.getValidationMessage(), "validation message");

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior for a control created with all elements, but with the
   * validation results flipped.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithAllElementsFlippedResult()
         throws Exception
  {
    UniquenessResponseControl c = new UniquenessResponseControl(
         "another-uniqueness-id", false, true, "validation message");

    c = new UniquenessResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.53");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertTrue(c.uniquenessConflictFound());

    assertNotNull(c.getUniquenessID());
    assertEquals(c.getUniquenessID(), "another-uniqueness-id");

    assertNotNull(c.getPreCommitValidationResult());
    assertEquals(c.getPreCommitValidationResult(),
         UniquenessValidationResult.VALIDATION_FAILED);

    assertNotNull(c.getPreCommitValidationPassed());
    assertEquals(c.getPreCommitValidationPassed(), Boolean.FALSE);

    assertNotNull(c.getPostCommitValidationResult());
    assertEquals(c.getPostCommitValidationResult(),
         UniquenessValidationResult.VALIDATION_PASSED);

    assertNotNull(c.getPostCommitValidationPassed());
    assertEquals(c.getPostCommitValidationPassed(), Boolean.TRUE);

    assertNotNull(c.getValidationMessage());
    assertEquals(c.getValidationMessage(), "validation message");

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the get method in an {@code LDAPResult} that does not
   * have any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNoControls()
         throws Exception
  {
    final LDAPResult result = new LDAPResult(1, ResultCode.SUCCESS);
    assertNotNull(UniquenessResponseControl.get(result));
    assertTrue(UniquenessResponseControl.get(result).isEmpty());
  }



  /**
   * Tests the behavior of the get method in an {@code LDAPResult} that has a
   * set of controls that does not include the uniqueness response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetControlsDoesNotIncludeUniquenessResponse()
         throws Exception
  {
    final Control[] responseControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false)
    };

    final LDAPResult result = new LDAPResult(1, ResultCode.SUCCESS, null,
         null, null, responseControls);
    assertNotNull(UniquenessResponseControl.get(result));
    assertTrue(UniquenessResponseControl.get(result).isEmpty());
  }



  /**
   * Tests the behavior of the get method in an {@code LDAPResult} that has a
   * pair of uniqueness response controls with different uniqueness IDs.  The
   * first control will be pre-decoded, while the second will not be.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetHasMultipleUniquenessResponseControlsWithDifferentIDs()
         throws Exception
  {
    final UniquenessResponseControl urc1 = new UniquenessResponseControl("id1",
         true, true, null);
    final UniquenessResponseControl urc2 = new UniquenessResponseControl("id2",
         true, false, "post-commit conflict detected");

    final Control[] responseControls =
    {
      urc1,
      new Control(urc2.getOID(), urc2.isCritical(), urc2.getValue())
    };

    final LDAPResult result = new LDAPResult(1, ResultCode.SUCCESS, null,
         null, null, responseControls);
    assertNotNull(UniquenessResponseControl.get(result));
    assertFalse(UniquenessResponseControl.get(result).isEmpty());
    assertEquals(UniquenessResponseControl.get(result).size(), 2);
    assertTrue(UniquenessResponseControl.get(result).containsKey("id1"));
    assertTrue(UniquenessResponseControl.get(result).containsKey("id2"));
  }



  /**
   * Tests the behavior of the get method in an {@code LDAPResult} that has a
   * malformed uniqueness response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetHasMalformedControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.53", false,
           new ASN1OctetString("malformed"))
    };

    final LDAPResult result = new LDAPResult(1, ResultCode.SUCCESS, null,
         null, null, responseControls);
    UniquenessResponseControl.get(result);
  }



  /**
   * Tests the behavior of the get method in an {@code LDAPResult} that has a
   * pair of uniqueness response controls with conflicting uniqueness IDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetHasMultipleUniquenessResponseControlsWithConflictingIDs()
         throws Exception
  {
    final UniquenessResponseControl urc1 = new UniquenessResponseControl("id1",
         true, true, null);
    final UniquenessResponseControl urc2 = new UniquenessResponseControl("id2",
         true, false, "post-commit conflict detected");

    final Control[] responseControls =
    {
      new UniquenessResponseControl("id", true, true, null),
      new UniquenessResponseControl("id", true, true, null)
    };

    final LDAPResult result = new LDAPResult(1, ResultCode.SUCCESS, null,
         null, null, responseControls);
    UniquenessResponseControl.get(result);
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
    new UniquenessResponseControl().decodeControl("1.3.6.1.4.1.30221.2.5.53",
        false, null);
  }



  /**
   * Tests the behavior when trying to decode a control whose value is not a
   * BER sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotSequence()
         throws Exception
  {
    new UniquenessResponseControl().decodeControl("1.3.6.1.4.1.30221.2.5.53",
        false, new ASN1OctetString("malformed"));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence has
   * an unrecognized element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceUnrecognizedElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "uniqueness-id"),
         new ASN1OctetString((byte) 0x8F, "unknown element type"));

    new UniquenessResponseControl().decodeControl("1.3.6.1.4.1.30221.2.5.53",
        false, new ASN1OctetString(valueSequence.encode()));
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
         new ASN1OctetString((byte) 0x83, "validation message"));

    new UniquenessResponseControl().decodeControl("1.3.6.1.4.1.30221.2.5.53",
        false, new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when only a uniqueness ID is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlOnlyUniquenessID()
          throws Exception
  {
    final UniquenessResponseControl c =
         new UniquenessResponseControl("TheUniquenessID", null, null, null);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("uniqueness-id", "TheUniquenessID")));


    UniquenessResponseControl decodedControl =
         UniquenessResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), "TheUniquenessID");

    assertNull(decodedControl.getPreCommitValidationPassed());

    assertNull(decodedControl.getPostCommitValidationPassed());

    assertNull(decodedControl.getValidationMessage());


    decodedControl =
         (UniquenessResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), "TheUniquenessID");

    assertNull(decodedControl.getPreCommitValidationPassed());

    assertNull(decodedControl.getPostCommitValidationPassed());

    assertNull(decodedControl.getValidationMessage());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when all elements are specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAllElements()
          throws Exception
  {
    final UniquenessResponseControl c =
         new UniquenessResponseControl("TheUniquenessID", true, false,
              "TheValidationMessage");

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("uniqueness-id", "TheUniquenessID"),
              new JSONField("pre-commit-validation-passed", true),
              new JSONField("post-commit-validation-passed", false),
              new JSONField("validation-message", "TheValidationMessage")));


    UniquenessResponseControl decodedControl =
         UniquenessResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), "TheUniquenessID");

    assertEquals(decodedControl.getPreCommitValidationPassed(),
         Boolean.TRUE);

    assertEquals(decodedControl.getPostCommitValidationPassed(),
         Boolean.FALSE);

    assertEquals(decodedControl.getValidationMessage(), "TheValidationMessage");


    decodedControl =
         (UniquenessResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), "TheUniquenessID");

    assertEquals(decodedControl.getPreCommitValidationPassed(),
         Boolean.TRUE);

    assertEquals(decodedControl.getPostCommitValidationPassed(),
         Boolean.FALSE);

    assertEquals(decodedControl.getValidationMessage(), "TheValidationMessage");
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
    final UniquenessResponseControl c =
         new UniquenessResponseControl("TheUniquenessID", true, false,
              "TheValidationMessage");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    UniquenessResponseControl decodedControl =
         UniquenessResponseControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), "TheUniquenessID");

    assertEquals(decodedControl.getPreCommitValidationPassed(),
         Boolean.TRUE);

    assertEquals(decodedControl.getPostCommitValidationPassed(),
         Boolean.FALSE);

    assertEquals(decodedControl.getValidationMessage(), "TheValidationMessage");


    decodedControl =
         (UniquenessResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), "TheUniquenessID");

    assertEquals(decodedControl.getPreCommitValidationPassed(),
         Boolean.TRUE);

    assertEquals(decodedControl.getPostCommitValidationPassed(),
         Boolean.FALSE);

    assertEquals(decodedControl.getValidationMessage(), "TheValidationMessage");
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the uniqueness-id field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlMissingUniquenessID()
          throws Exception
  {
    final UniquenessResponseControl c =
         new UniquenessResponseControl("TheUniquenessID", true, false,
              "TheValidationMessage");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("pre-commit-validation-passed", true),
              new JSONField("post-commit-validation-passed", false),
              new JSONField("validation-message", "TheValidationMessage"))));


    UniquenessResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlUnrecognizedFieldStrict()
          throws Exception
  {
    final UniquenessResponseControl c =
         new UniquenessResponseControl("TheUniquenessID", true, false,
              "TheValidationMessage");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("uniqueness-id", "TheUniquenessID"),
              new JSONField("pre-commit-validation-passed", true),
              new JSONField("post-commit-validation-passed", false),
              new JSONField("validation-message", "TheValidationMessage"),
              new JSONField("unrecognized", "foo"))));


    UniquenessResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlUnrecognizedFieldNonStrict()
          throws Exception
  {
    final UniquenessResponseControl c =
         new UniquenessResponseControl("TheUniquenessID", true, false,
              "TheValidationMessage");

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("uniqueness-id", "TheUniquenessID"),
              new JSONField("pre-commit-validation-passed", true),
              new JSONField("post-commit-validation-passed", false),
              new JSONField("validation-message", "TheValidationMessage"),
              new JSONField("unrecognized", "foo"))));


    UniquenessResponseControl decodedControl =
         UniquenessResponseControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), "TheUniquenessID");

    assertEquals(decodedControl.getPreCommitValidationPassed(),
         Boolean.TRUE);

    assertEquals(decodedControl.getPostCommitValidationPassed(),
         Boolean.FALSE);

    assertEquals(decodedControl.getValidationMessage(), "TheValidationMessage");


    decodedControl =
         (UniquenessResponseControl)
         Control.decodeJSONControl(controlObject, false, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getUniquenessID(), "TheUniquenessID");

    assertEquals(decodedControl.getPreCommitValidationPassed(),
         Boolean.TRUE);

    assertEquals(decodedControl.getPostCommitValidationPassed(),
         Boolean.FALSE);

    assertEquals(decodedControl.getValidationMessage(), "TheValidationMessage");
  }
}
