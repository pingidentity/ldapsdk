/*
 * Copyright 2007-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2024 Ping Identity Corporation
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
 * Copyright (C) 2007-2024 Ping Identity Corporation
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
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the VirtualListViewRequestControl
 * class.
 */
public class VirtualListViewRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a non-{@code null} context ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 9, 0, new ASN1OctetString());
    c = new VirtualListViewRequestControl(c);

    assertEquals(c.getTargetOffset(), 1);
    assertEquals(c.getContentCount(), 0);

    assertNull(c.getAssertionValueString());
    assertNull(c.getAssertionValueBytes());
    assertNull(c.getAssertionValue());

    assertEquals(c.getBeforeCount(), 0);
    assertEquals(c.getAfterCount(), 9);

    assertNotNull(c.getContextID());

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with a {@code null} context ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NullContextID()
         throws Exception
  {
    VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 9, 0, null);
    c = new VirtualListViewRequestControl(c);

    assertEquals(c.getTargetOffset(), 1);
    assertEquals(c.getContentCount(), 0);

    assertNull(c.getAssertionValueString());
    assertNull(c.getAssertionValueBytes());
    assertNull(c.getAssertionValue());

    assertEquals(c.getBeforeCount(), 0);
    assertEquals(c.getAfterCount(), 9);

    assertNull(c.getContextID());

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a non-{@code null} context ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    VirtualListViewRequestControl c =
         new VirtualListViewRequestControl("foo", 0, 9, new ASN1OctetString());
    c = new VirtualListViewRequestControl(c);

    assertEquals(c.getTargetOffset(), -1);
    assertEquals(c.getContentCount(), -1);

    assertNotNull(c.getAssertionValueString());
    assertNotNull(c.getAssertionValueBytes());
    assertNotNull(c.getAssertionValue());

    assertEquals(c.getBeforeCount(), 0);
    assertEquals(c.getAfterCount(), 9);

    assertNotNull(c.getContextID());

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a {@code null} context ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NullContextID()
         throws Exception
  {
    VirtualListViewRequestControl c =
         new VirtualListViewRequestControl("foo", 0, 9, null);
    c = new VirtualListViewRequestControl(c);

    assertEquals(c.getTargetOffset(), -1);
    assertEquals(c.getContentCount(), -1);

    assertNotNull(c.getAssertionValueString());
    assertNotNull(c.getAssertionValueBytes());
    assertNotNull(c.getAssertionValue());

    assertEquals(c.getBeforeCount(), 0);
    assertEquals(c.getAfterCount(), 9);

    assertNull(c.getContextID());

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
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
    VirtualListViewRequestControl c =
         new VirtualListViewRequestControl("foo".getBytes("UTF-8"), 0, 9, null);
    c = new VirtualListViewRequestControl(c);

    assertEquals(c.getTargetOffset(), -1);
    assertEquals(c.getContentCount(), -1);

    assertNotNull(c.getAssertionValueString());
    assertNotNull(c.getAssertionValueBytes());
    assertNotNull(c.getAssertionValue());

    assertEquals(c.getBeforeCount(), 0);
    assertEquals(c.getAfterCount(), 9);

    assertNull(c.getContextID());

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(new ASN1OctetString("foo"), 0, 9,
                                           null);
    c = new VirtualListViewRequestControl(c);

    assertEquals(c.getTargetOffset(), -1);
    assertEquals(c.getContentCount(), -1);

    assertNotNull(c.getAssertionValueString());
    assertNotNull(c.getAssertionValueBytes());
    assertNotNull(c.getAssertionValue());

    assertEquals(c.getBeforeCount(), 0);
    assertEquals(c.getAfterCount(), 9);

    assertNull(c.getContextID());

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fifth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5()
         throws Exception
  {
    VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 9, 0, null, false);
    c = new VirtualListViewRequestControl(c);

    assertEquals(c.getTargetOffset(), 1);
    assertEquals(c.getContentCount(), 0);

    assertNull(c.getAssertionValueString());
    assertNull(c.getAssertionValueBytes());
    assertNull(c.getAssertionValue());

    assertEquals(c.getBeforeCount(), 0);
    assertEquals(c.getAfterCount(), 9);

    assertNull(c.getContextID());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the sixth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6()
         throws Exception
  {
    VirtualListViewRequestControl c =
         new VirtualListViewRequestControl("foo", 0, 9, null, false);
    c = new VirtualListViewRequestControl(c);

    assertEquals(c.getTargetOffset(), -1);
    assertEquals(c.getContentCount(), -1);

    assertNotNull(c.getAssertionValueString());
    assertNotNull(c.getAssertionValueBytes());
    assertNotNull(c.getAssertionValue());

    assertEquals(c.getBeforeCount(), 0);
    assertEquals(c.getAfterCount(), 9);

    assertNull(c.getContextID());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the seventh constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7()
         throws Exception
  {
    VirtualListViewRequestControl c =
         new VirtualListViewRequestControl("foo".getBytes("UTF-8"), 0, 9, null,
                                           false);
    c = new VirtualListViewRequestControl(c);

    assertEquals(c.getTargetOffset(), -1);
    assertEquals(c.getContentCount(), -1);

    assertNotNull(c.getAssertionValueString());
    assertNotNull(c.getAssertionValueBytes());
    assertNotNull(c.getAssertionValue());

    assertEquals(c.getBeforeCount(), 0);
    assertEquals(c.getAfterCount(), 9);

    assertNull(c.getContextID());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the eighth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8()
         throws Exception
  {
    VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(new ASN1OctetString("foo"), 0, 9,
                                           null, false);
    c = new VirtualListViewRequestControl(c);

    assertEquals(c.getTargetOffset(), -1);
    assertEquals(c.getContentCount(), -1);

    assertNotNull(c.getAssertionValueString());
    assertNotNull(c.getAssertionValueBytes());
    assertNotNull(c.getAssertionValue());

    assertEquals(c.getBeforeCount(), 0);
    assertEquals(c.getAfterCount(), 9);

    assertNull(c.getContextID());

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the ninth constructor with a generic control with no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor9NoValue()
         throws Exception
  {
    Control c = new Control(
         VirtualListViewRequestControl.VIRTUAL_LIST_VIEW_REQUEST_OID,
         true, null);
    c = new VirtualListViewRequestControl(c);
  }



  /**
   * Tests the ninth constructor with a generic control with a value that isn't
   * a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor9ValueNotSequence()
         throws Exception
  {
    Control c = new Control(
         VirtualListViewRequestControl.VIRTUAL_LIST_VIEW_REQUEST_OID,
         true, new ASN1OctetString("foo"));
    c = new VirtualListViewRequestControl(c);
  }



  /**
   * Tests the ninth constructor with a generic control with a value sequence
   * whose third element contains an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor9ValueSequenceInvalid()
         throws Exception
  {
    ASN1Element[] elements =
    {
       new ASN1Integer(0),
       new ASN1Integer(0),
       new ASN1OctetString("foo")
    };

    Control c = new Control(
         VirtualListViewRequestControl.VIRTUAL_LIST_VIEW_REQUEST_OID,
         true, new ASN1OctetString(new ASN1Sequence(elements).encode()));
    c = new VirtualListViewRequestControl(c);
  }



  /**
   * Add multiple entries to the server and then iterate through them three at a
   * time using the VLV control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithSortAndVLVControls()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    for (int i=0; i < 10; i++)
    {
      String dn = "ou=" + i + "," + getTestBaseDN();
      Attribute[] attrs =
      {
        new Attribute("objectClass", "top", "organizationalUnit"),
        new Attribute("ou", String.valueOf(i))
      };

      conn.add(dn, attrs);
    }


    int             iterationCount = 0;
    int             targetPosition = 1;
    int             contentCount   = 0;
    ASN1OctetString contextID      = null;
    do
    {
      iterationCount++;
      Control[] controls =
      {
        new ServerSideSortRequestControl(true, new SortKey("ou", false)),
        new VirtualListViewRequestControl(targetPosition, 0, 2, contentCount,
                                          contextID)
      };

      SearchRequest searchRequest =
           new SearchRequest(getTestBaseDN(), SearchScope.ONE,
                             "(objectClass=*)");
      searchRequest.setControls(controls);

      SearchResult searchResult = conn.search(searchRequest);

      boolean sortResultFound = false;
      boolean vlvResultFound  = false;
      for (Control c : searchResult.getResponseControls())
      {
        if (c instanceof ServerSideSortResponseControl)
        {
          ServerSideSortResponseControl sssrc =
               (ServerSideSortResponseControl) c;
          assertEquals(sssrc.getResultCode(), ResultCode.SUCCESS);
          assertNull(sssrc.getAttributeName());
          assertNotNull(sssrc.toString());

          sortResultFound = true;
        }
        else if (c instanceof VirtualListViewResponseControl)
        {
          VirtualListViewResponseControl vlvrc =
               (VirtualListViewResponseControl) c;
          assertEquals(vlvrc.getResultCode(), ResultCode.SUCCESS);
          assertTrue((contentCount = vlvrc.getContentCount()) > 0);
          assertNotNull(vlvrc.toString());

          targetPosition =
               vlvrc.getTargetPosition() + searchResult.getEntryCount();
          contextID = vlvrc.getContextID();

          vlvResultFound = true;
        }
      }

      assertTrue(sortResultFound);
      assertTrue(vlvResultFound);
    } while (targetPosition < contentCount);

    assertTrue(iterationCount > 1);


    Control[] controls =
    {
      new SubtreeDeleteRequestControl()
    };

    conn.delete(new DeleteRequest(getTestBaseDN(), controls));
    conn.close();
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object using a target offset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlTargetOffset()
          throws Exception
  {
    final VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 99, 0, null);

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
              new JSONField("target-offset", 1),
              new JSONField("before-count", 0),
              new JSONField("after-count", 99),
              new JSONField("content-count", 0)));


    VirtualListViewRequestControl decodedControl =
         VirtualListViewRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getTargetOffset(), 1);

    assertNull(decodedControl.getAssertionValue());

    assertEquals(decodedControl.getBeforeCount(), 0);

    assertEquals(decodedControl.getAfterCount(), 99);

    assertEquals(decodedControl.getContentCount(), 0);

    assertNull(decodedControl.getContextID());


    decodedControl =
         (VirtualListViewRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getTargetOffset(), 1);

    assertNull(decodedControl.getAssertionValue());

    assertEquals(decodedControl.getBeforeCount(), 0);

    assertEquals(decodedControl.getAfterCount(), 99);

    assertEquals(decodedControl.getContentCount(), 0);

    assertNull(decodedControl.getContextID());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object using an assertion value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAssertionValue()
          throws Exception
  {
    final VirtualListViewRequestControl c =
         new VirtualListViewRequestControl("TheAssertionValue", 0, 99,
              new ASN1OctetString("TheContextID"));

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
              new JSONField("assertion-value", "TheAssertionValue"),
              new JSONField("before-count", 0),
              new JSONField("after-count", 99),
              new JSONField("context-id", Base64.encode("TheContextID"))));


    VirtualListViewRequestControl decodedControl =
         VirtualListViewRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getTargetOffset(), -1);

    assertEquals(decodedControl.getAssertionValue().stringValue(),
         "TheAssertionValue");

    assertEquals(decodedControl.getBeforeCount(), 0);

    assertEquals(decodedControl.getAfterCount(), 99);

    assertEquals(decodedControl.getContentCount(), -1);

    assertEquals(decodedControl.getContextID().stringValue(),
         "TheContextID");


    decodedControl =
         (VirtualListViewRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getTargetOffset(), -1);

    assertEquals(decodedControl.getAssertionValue().stringValue(),
         "TheAssertionValue");

    assertEquals(decodedControl.getBeforeCount(), 0);

    assertEquals(decodedControl.getAfterCount(), 99);

    assertEquals(decodedControl.getContentCount(), -1);

    assertEquals(decodedControl.getContextID().stringValue(),
         "TheContextID");
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
    final VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 99, 0, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    VirtualListViewRequestControl decodedControl =
         VirtualListViewRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getTargetOffset(), 1);

    assertNull(decodedControl.getAssertionValue());

    assertEquals(decodedControl.getBeforeCount(), 0);

    assertEquals(decodedControl.getAfterCount(), 99);

    assertEquals(decodedControl.getContentCount(), 0);

    assertNull(decodedControl.getContextID());


    decodedControl =
         (VirtualListViewRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getTargetOffset(), 1);

    assertNull(decodedControl.getAssertionValue());

    assertEquals(decodedControl.getBeforeCount(), 0);

    assertEquals(decodedControl.getAfterCount(), 99);

    assertEquals(decodedControl.getContentCount(), 0);

    assertNull(decodedControl.getContextID());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value does not have either a target offset or an assertion value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueNeitherTargetOffsetNorAssertionValue()
          throws Exception
  {
    final VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 99, 0, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("before-count", 123),
              new JSONField("after-count", 12345),
              new JSONField("content-count", 123456),
              new JSONField("context-id", Base64.encode("TheContextID")))));

    VirtualListViewRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has both a target offset and an assertion value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueBothTargetOffsetAndAssertionValue()
          throws Exception
  {
    final VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 99, 0, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("target-offset", 1234),
              new JSONField("assertion-value", "TheAssertionValue"),
              new JSONField("before-count", 123),
              new JSONField("after-count", 12345),
              new JSONField("context-id", Base64.encode("TheContextID")))));

    VirtualListViewRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the before-count field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingBeforeCount()
          throws Exception
  {
    final VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 99, 0, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("target-offset", 1234),
              new JSONField("after-count", 12345),
              new JSONField("content-count", 123456),
              new JSONField("context-id", Base64.encode("TheContextID")))));

    VirtualListViewRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is missing the after-count field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueMissingAfterCount()
          throws Exception
  {
    final VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 99, 0, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("target-offset", 1234),
              new JSONField("before-count", 123),
              new JSONField("content-count", 123456),
              new JSONField("context-id", Base64.encode("TheContextID")))));

    VirtualListViewRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has a target offset without an explicit content count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlTargetOffsetWithoutContentCount()
          throws Exception
  {
    final VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 99, 0, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("target-offset", 1234),
              new JSONField("before-count", 123),
              new JSONField("after-count", 12345),
              new JSONField("context-id", Base64.encode("TheContextID")))));


    VirtualListViewRequestControl decodedControl =
         VirtualListViewRequestControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getTargetOffset(), 1234);

    assertNull(decodedControl.getAssertionValue());

    assertEquals(decodedControl.getBeforeCount(), 123);

    assertEquals(decodedControl.getAfterCount(), 12345);

    assertEquals(decodedControl.getContentCount(), 0);

    assertEquals(decodedControl.getContextID().stringValue(), "TheContextID");


    decodedControl =
         (VirtualListViewRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getTargetOffset(), 1234);

    assertNull(decodedControl.getAssertionValue());

    assertEquals(decodedControl.getBeforeCount(), 123);

    assertEquals(decodedControl.getAfterCount(), 12345);

    assertEquals(decodedControl.getContentCount(), 0);

    assertEquals(decodedControl.getContextID().stringValue(), "TheContextID");
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has both an assertion value and a content count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueBothAssertionValueAndContentCount()
          throws Exception
  {
    final VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 99, 0, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("assertion-value", "TheAssertionValue"),
              new JSONField("before-count", 123),
              new JSONField("after-count", 12345),
              new JSONField("content-count", 123456),
              new JSONField("context-id", Base64.encode("TheContextID")))));

    VirtualListViewRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has a context-id value that is not valid base64.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueContextIDNotBase64()
          throws Exception
  {
    final VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 99, 0, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("target-offset", 1234),
              new JSONField("before-count", 123),
              new JSONField("after-count", 12345),
              new JSONField("content-count", 123456),
              new JSONField("context-id", "Not Valid Base64"))));

    VirtualListViewRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 99, 0, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("target-offset", 1234),
              new JSONField("before-count", 123),
              new JSONField("after-count", 12345),
              new JSONField("content-count", 123456),
              new JSONField("context-id", Base64.encode("TheContextID")),
              new JSONField("unrecognized", "foo"))));

    VirtualListViewRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrict()
          throws Exception
  {
    final VirtualListViewRequestControl c =
         new VirtualListViewRequestControl(1, 0, 99, 0, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("target-offset", 1234),
              new JSONField("before-count", 123),
              new JSONField("after-count", 12345),
              new JSONField("content-count", 123456),
              new JSONField("context-id", Base64.encode("TheContextID")),
              new JSONField("unrecognized", "foo"))));


    VirtualListViewRequestControl decodedControl =
         VirtualListViewRequestControl.decodeJSONControl(controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getTargetOffset(), 1234);

    assertNull(decodedControl.getAssertionValue());

    assertEquals(decodedControl.getBeforeCount(), 123);

    assertEquals(decodedControl.getAfterCount(), 12345);

    assertEquals(decodedControl.getContentCount(), 123456);

    assertEquals(decodedControl.getContextID().stringValue(), "TheContextID");


    decodedControl =
         (VirtualListViewRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getTargetOffset(), 1234);

    assertNull(decodedControl.getAssertionValue());

    assertEquals(decodedControl.getBeforeCount(), 123);

    assertEquals(decodedControl.getAfterCount(), 12345);

    assertEquals(decodedControl.getContentCount(), 123456);

    assertEquals(decodedControl.getContextID().stringValue(), "TheContextID");
  }
}
