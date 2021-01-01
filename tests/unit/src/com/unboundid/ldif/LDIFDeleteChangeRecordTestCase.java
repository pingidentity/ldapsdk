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

import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the LDIFDeleteChangeRecord class.
 */
public class LDIFDeleteChangeRecordTestCase
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
    LDIFDeleteChangeRecord r = new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    DeleteRequest deleteRequest = r.toDeleteRequest();
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.DELETE);

    String[] ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 2);

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

    assertNotNull(r.getControls());
    assertTrue(r.getControls().isEmpty());


    r = r.duplicate();

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    deleteRequest = r.toDeleteRequest();
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.DELETE);

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 2);

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

    assertNotNull(r.getControls());
    assertTrue(r.getControls().isEmpty());


    r = r.duplicate((Control[]) null);

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    deleteRequest = r.toDeleteRequest();
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.DELETE);

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 2);

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

    assertNotNull(r.getControls());
    assertTrue(r.getControls().isEmpty());


    r = r.duplicate(new Control[0]);

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    deleteRequest = r.toDeleteRequest();
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.DELETE);

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 2);

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

    assertNotNull(r.getControls());
    assertTrue(r.getControls().isEmpty());


    r = r.duplicate(new ManageDsaITRequestControl(false));

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    deleteRequest = r.toDeleteRequest();
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.DELETE);

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 3);

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

    assertNotNull(r.getControls());
    assertFalse(r.getControls().isEmpty());
    assertEquals(r.getControls(),
         Collections.singletonList(new ManageDsaITRequestControl(false)));


    r = r.duplicate(new ManageDsaITRequestControl(false),
         new SubtreeDeleteRequestControl(false));

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    deleteRequest = r.toDeleteRequest();
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.DELETE);

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 4);

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

    assertNotNull(r.getControls());
    assertFalse(r.getControls().isEmpty());
    assertEquals(r.getControls(),
         Arrays.asList(new ManageDsaITRequestControl(false),
              new SubtreeDeleteRequestControl(false)));
  }



  /**
   * Tests the first constructor with a {@code null} DN.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullDN()
  {
    new LDIFDeleteChangeRecord((String) null);
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
    LDIFDeleteChangeRecord r =
         new LDIFDeleteChangeRecord(new DeleteRequest("dc=example,dc=com"));

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    DeleteRequest deleteRequest = r.toDeleteRequest();
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.DELETE);

    String[] ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 2);

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
  }



  /**
   * Tests the second constructor with a {@code null} delete request.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class,
                               NullPointerException.class  })
  public void testConstructor2NullDeleteRequest()
  {
    new LDIFDeleteChangeRecord((DeleteRequest) null);
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
    LDIFDeleteChangeRecord r = new LDIFDeleteChangeRecord("invalid");

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
    LDIFDeleteChangeRecord r = new LDIFDeleteChangeRecord("dc=example,dc=com");

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
    LDIFDeleteChangeRecord r = new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertTrue(r.equals(r));
  }



  /**
   * Tests the {@code equals} method with an equivalent object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalent()
         throws Exception
  {
    LDIFDeleteChangeRecord r1 = new LDIFDeleteChangeRecord("dc=example,dc=com");
    LDIFDeleteChangeRecord r2 = new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertTrue(r1.equals(r2));
  }



  /**
   * Tests the {@code equals} method with a change record that has an invalid
   * DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsRecordWithInvalidDN()
         throws Exception
  {
    LDIFDeleteChangeRecord r1 = new LDIFDeleteChangeRecord("dc=example,dc=com");
    LDIFDeleteChangeRecord r2 = new LDIFDeleteChangeRecord("invalid");

    assertFalse(r1.equals(r2));
  }



  /**
   * Tests the {@code equals} method with an object that is not a change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotChangeRecord()
         throws Exception
  {
    LDIFDeleteChangeRecord r = new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertFalse(r.equals("not change record"));
  }



  /**
   * Tests the {@code equals} method with an object that is a change record but
   * not a delete change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotDeleteChangeRecord()
         throws Exception
  {
    LDIFDeleteChangeRecord r1 = new LDIFDeleteChangeRecord("dc=example,dc=com");

    LDIFAddChangeRecord r2 = new LDIFAddChangeRecord(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    assertFalse(r1.equals(r2));
  }
}
