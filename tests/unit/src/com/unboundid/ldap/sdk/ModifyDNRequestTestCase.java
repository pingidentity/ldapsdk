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
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the ModifyDNRequest class.
 */
public class ModifyDNRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which takes string DN and newRDN values and a
   * deleteOldRDN flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true);
    modifyDNRequest = modifyDNRequest.duplicate();

    assertNotNull(modifyDNRequest.getDN());
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(modifyDNRequest.getNewRDN());
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    assertTrue(modifyDNRequest.deleteOldRDN());

    assertNull(modifyDNRequest.getNewSuperiorDN());

    assertFalse(modifyDNRequest.hasControl());
    assertFalse(modifyDNRequest.hasControl("1.2.3.4"));
    assertNull(modifyDNRequest.getControl("1.2.3.4"));
    assertNotNull(modifyDNRequest.getControls());
    assertEquals(modifyDNRequest.getControls().length, 0);

    assertNotNull(modifyDNRequest.toLDIFChangeRecord());

    assertNotNull(modifyDNRequest.toLDIF());
    assertTrue(modifyDNRequest.toLDIF().length > 0);

    assertNotNull(modifyDNRequest.toLDIFString());

    assertNotNull(modifyDNRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyDNRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyDNRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyDNRequest);

    assertEquals(modifyDNRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST);

    assertNull(modifyDNRequest.getIntermediateResponseListener());
    modifyDNRequest.setIntermediateResponseListener(
         new TestIntermediateResponseListener());
    assertNotNull(modifyDNRequest.getIntermediateResponseListener());
    modifyDNRequest.setIntermediateResponseListener(null);
    assertNull(modifyDNRequest.getIntermediateResponseListener());
  }



  /**
   * Tests the first constructor, which takes string DN and newRDN values and a
   * deleteOldRDN flag, with null DN and newRDN values.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1Null()
  {
    new ModifyDNRequest((String) null, (String) null, true);
  }



  /**
   * Tests the second constructor, which takes DN and newRDN objects and a
   * deleteOldRDN flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest(new DN("ou=People,dc=example,dc=com"),
                             new RDN("ou=Users"), true);
    modifyDNRequest.setFollowReferrals(true);
    modifyDNRequest = modifyDNRequest.duplicate();

    assertNotNull(modifyDNRequest.getDN());
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(modifyDNRequest.getNewRDN());
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    assertTrue(modifyDNRequest.deleteOldRDN());

    assertNull(modifyDNRequest.getNewSuperiorDN());

    assertFalse(modifyDNRequest.hasControl());
    assertFalse(modifyDNRequest.hasControl("1.2.3.4"));
    assertNull(modifyDNRequest.getControl("1.2.3.4"));
    assertNotNull(modifyDNRequest.getControls());
    assertEquals(modifyDNRequest.getControls().length, 0);

    assertNotNull(modifyDNRequest.toLDIFChangeRecord());

    assertNotNull(modifyDNRequest.toLDIF());
    assertTrue(modifyDNRequest.toLDIF().length > 0);

    assertNotNull(modifyDNRequest.toLDIFString());

    assertNotNull(modifyDNRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyDNRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyDNRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the first constructor, which takes DN and newRDN objects and a
   * deleteOldRDN flag, with null DN and newRDN values.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2Null()
  {
    new ModifyDNRequest((DN) null, (RDN) null, true);
  }



  /**
   * Tests the third constructor, which takes string DN and newRDN values, a
   * deleteOldRDN flag, and a string newSuperior DN, using a non-null
   * newSuperior DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true,
                             "o=example.com");
    modifyDNRequest.setFollowReferrals(false);
    modifyDNRequest = modifyDNRequest.duplicate();

    assertNotNull(modifyDNRequest.getDN());
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(modifyDNRequest.getNewRDN());
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    assertTrue(modifyDNRequest.deleteOldRDN());

    assertNotNull(modifyDNRequest.getNewSuperiorDN());
    assertEquals(modifyDNRequest.getNewSuperiorDN(), "o=example.com");

    assertFalse(modifyDNRequest.hasControl());
    assertFalse(modifyDNRequest.hasControl("1.2.3.4"));
    assertNull(modifyDNRequest.getControl("1.2.3.4"));
    assertNotNull(modifyDNRequest.getControls());
    assertEquals(modifyDNRequest.getControls().length, 0);

    assertNotNull(modifyDNRequest.toLDIFChangeRecord());

    assertNotNull(modifyDNRequest.toLDIF());
    assertTrue(modifyDNRequest.toLDIF().length > 0);

    assertNotNull(modifyDNRequest.toLDIFString());

    assertNotNull(modifyDNRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyDNRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyDNRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the third constructor, which takes string DN and newRDN values, a
   * deleteOldRDN flag, and a string newSuperior DN, using a null newSuperior
   * DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullNewSuperior()
         throws Exception
  {
    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true,
                             (String) null);
    modifyDNRequest = modifyDNRequest.duplicate();

    assertNotNull(modifyDNRequest.getDN());
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(modifyDNRequest.getNewRDN());
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    assertTrue(modifyDNRequest.deleteOldRDN());

    assertNull(modifyDNRequest.getNewSuperiorDN());

    assertFalse(modifyDNRequest.hasControl());
    assertFalse(modifyDNRequest.hasControl("1.2.3.4"));
    assertNull(modifyDNRequest.getControl("1.2.3.4"));
    assertNotNull(modifyDNRequest.getControls());
    assertEquals(modifyDNRequest.getControls().length, 0);

    assertNotNull(modifyDNRequest.toLDIFChangeRecord());

    assertNotNull(modifyDNRequest.toLDIF());
    assertTrue(modifyDNRequest.toLDIF().length > 0);

    assertNotNull(modifyDNRequest.toLDIFString());

    assertNotNull(modifyDNRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyDNRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyDNRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the fourth constructor, which takes DN and newRDN objects, a
   * deleteOldRDN flag, and a newSuperior DN, using a non-null newSuperior DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest(new DN("ou=People,dc=example,dc=com"),
                             new RDN("ou=Users"), true,
                             new DN("o=example.com"));
    modifyDNRequest = modifyDNRequest.duplicate();

    assertNotNull(modifyDNRequest.getDN());
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(modifyDNRequest.getNewRDN());
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    assertTrue(modifyDNRequest.deleteOldRDN());

    assertNotNull(modifyDNRequest.getNewSuperiorDN());
    assertEquals(modifyDNRequest.getNewSuperiorDN(), "o=example.com");

    assertFalse(modifyDNRequest.hasControl());
    assertFalse(modifyDNRequest.hasControl("1.2.3.4"));
    assertNull(modifyDNRequest.getControl("1.2.3.4"));
    assertNotNull(modifyDNRequest.getControls());
    assertEquals(modifyDNRequest.getControls().length, 0);

    assertNotNull(modifyDNRequest.toLDIFChangeRecord());

    assertNotNull(modifyDNRequest.toLDIF());
    assertTrue(modifyDNRequest.toLDIF().length > 0);

    assertNotNull(modifyDNRequest.toLDIFString());

    assertNotNull(modifyDNRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyDNRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyDNRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the fourth constructor, which takes DN and newRDN objects, a
   * deleteOldRDN flag, and a newSuperior DN, using a null newSuperior DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NullNewSuperior()
         throws Exception
  {
    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest(new DN("ou=People,dc=example,dc=com"),
                             new RDN("ou=Users"), true, (DN) null);
    modifyDNRequest = modifyDNRequest.duplicate();

    assertNotNull(modifyDNRequest.getDN());
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(modifyDNRequest.getNewRDN());
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    assertTrue(modifyDNRequest.deleteOldRDN());

    assertNull(modifyDNRequest.getNewSuperiorDN());

    assertFalse(modifyDNRequest.hasControl());
    assertFalse(modifyDNRequest.hasControl("1.2.3.4"));
    assertNull(modifyDNRequest.getControl("1.2.3.4"));
    assertNotNull(modifyDNRequest.getControls());
    assertEquals(modifyDNRequest.getControls().length, 0);

    assertNotNull(modifyDNRequest.toLDIFChangeRecord());

    assertNotNull(modifyDNRequest.toLDIF());
    assertTrue(modifyDNRequest.toLDIF().length > 0);

    assertNotNull(modifyDNRequest.toLDIFString());

    assertNotNull(modifyDNRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyDNRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyDNRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the fifth constructor, which takes string DN and newRDN values, a
   * deleteOldRDN flag, and set of controls.
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

    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true,
                             controls);
    modifyDNRequest = modifyDNRequest.duplicate();

    assertNotNull(modifyDNRequest.getDN());
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(modifyDNRequest.getNewRDN());
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    assertTrue(modifyDNRequest.deleteOldRDN());

    assertNull(modifyDNRequest.getNewSuperiorDN());

    assertTrue(modifyDNRequest.hasControl());
    assertTrue(modifyDNRequest.hasControl("1.2.3.4"));
    assertNotNull(modifyDNRequest.getControl("1.2.3.4"));
    assertFalse(modifyDNRequest.hasControl("1.2.3.6"));
    assertNull(modifyDNRequest.getControl("1.2.3.6"));
    assertNotNull(modifyDNRequest.getControls());
    assertEquals(modifyDNRequest.getControls().length, 2);

    assertNotNull(modifyDNRequest.toLDIFChangeRecord());

    assertNotNull(modifyDNRequest.toLDIF());
    assertTrue(modifyDNRequest.toLDIF().length > 0);

    assertNotNull(modifyDNRequest.toLDIFString());

    assertNotNull(modifyDNRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyDNRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyDNRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the sixth constructor, which takes DN and newRDN objects, a
   * deleteOldRDN flag, and set of controls.
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

    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest(new DN("ou=People,dc=example,dc=com"),
                             new RDN("ou=Users"), true, controls);
    modifyDNRequest = modifyDNRequest.duplicate();

    assertNotNull(modifyDNRequest.getDN());
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(modifyDNRequest.getNewRDN());
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    assertTrue(modifyDNRequest.deleteOldRDN());

    assertNull(modifyDNRequest.getNewSuperiorDN());

    assertTrue(modifyDNRequest.hasControl());
    assertTrue(modifyDNRequest.hasControl("1.2.3.4"));
    assertNotNull(modifyDNRequest.getControl("1.2.3.4"));
    assertFalse(modifyDNRequest.hasControl("1.2.3.6"));
    assertNull(modifyDNRequest.getControl("1.2.3.6"));
    assertNotNull(modifyDNRequest.getControls());
    assertEquals(modifyDNRequest.getControls().length, 2);

    assertNotNull(modifyDNRequest.toLDIFChangeRecord());

    assertNotNull(modifyDNRequest.toLDIF());
    assertTrue(modifyDNRequest.toLDIF().length > 0);

    assertNotNull(modifyDNRequest.toLDIFString());

    assertNotNull(modifyDNRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyDNRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyDNRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the seventh constructor, which takes string DN and newRDN values, a
   * deleteOldRDN flag, a string newSuperior DN, and set of controls.
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

    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true,
                             "o=example.com", controls);
    modifyDNRequest = modifyDNRequest.duplicate();

    assertNotNull(modifyDNRequest.getDN());
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(modifyDNRequest.getNewRDN());
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    assertTrue(modifyDNRequest.deleteOldRDN());

    assertNotNull(modifyDNRequest.getNewSuperiorDN());
    assertEquals(modifyDNRequest.getNewSuperiorDN(), "o=example.com");

    assertTrue(modifyDNRequest.hasControl());
    assertTrue(modifyDNRequest.hasControl("1.2.3.4"));
    assertNotNull(modifyDNRequest.getControl("1.2.3.4"));
    assertFalse(modifyDNRequest.hasControl("1.2.3.6"));
    assertNull(modifyDNRequest.getControl("1.2.3.6"));
    assertNotNull(modifyDNRequest.getControls());
    assertEquals(modifyDNRequest.getControls().length, 2);

    assertNotNull(modifyDNRequest.toLDIFChangeRecord());

    assertNotNull(modifyDNRequest.toLDIF());
    assertTrue(modifyDNRequest.toLDIF().length > 0);

    assertNotNull(modifyDNRequest.toLDIFString());

    assertNotNull(modifyDNRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyDNRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyDNRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the seventh constructor, which takes string DN and newRDN values, a
   * deleteOldRDN flag, a string newSuperior DN, and set of controls, using a
   * null newSuperiorDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7NullNewSuperior()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true,
                             null, controls);
    modifyDNRequest = modifyDNRequest.duplicate();

    assertNotNull(modifyDNRequest.getDN());
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(modifyDNRequest.getNewRDN());
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    assertTrue(modifyDNRequest.deleteOldRDN());

    assertNull(modifyDNRequest.getNewSuperiorDN());

    assertTrue(modifyDNRequest.hasControl());
    assertTrue(modifyDNRequest.hasControl("1.2.3.4"));
    assertNotNull(modifyDNRequest.getControl("1.2.3.4"));
    assertFalse(modifyDNRequest.hasControl("1.2.3.6"));
    assertNull(modifyDNRequest.getControl("1.2.3.6"));
    assertNotNull(modifyDNRequest.getControls());
    assertEquals(modifyDNRequest.getControls().length, 2);

    assertNotNull(modifyDNRequest.toLDIFChangeRecord());

    assertNotNull(modifyDNRequest.toLDIF());
    assertTrue(modifyDNRequest.toLDIF().length > 0);

    assertNotNull(modifyDNRequest.toLDIFString());

    assertNotNull(modifyDNRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyDNRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyDNRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the eighth constructor, which takes DN and newRDN objects, a
   * deleteOldRDN flag, a newSuperior DN, and set of controls.
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

    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest(new DN("ou=People,dc=example,dc=com"),
                             new RDN("ou=Users"), true,
                             new DN("o=example.com"), controls);
    modifyDNRequest = modifyDNRequest.duplicate();

    assertNotNull(modifyDNRequest.getDN());
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(modifyDNRequest.getNewRDN());
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    assertTrue(modifyDNRequest.deleteOldRDN());

    assertNotNull(modifyDNRequest.getNewSuperiorDN());
    assertEquals(modifyDNRequest.getNewSuperiorDN(), "o=example.com");

    assertTrue(modifyDNRequest.hasControl());
    assertTrue(modifyDNRequest.hasControl("1.2.3.4"));
    assertNotNull(modifyDNRequest.getControl("1.2.3.4"));
    assertFalse(modifyDNRequest.hasControl("1.2.3.6"));
    assertNull(modifyDNRequest.getControl("1.2.3.6"));
    assertNotNull(modifyDNRequest.getControls());
    assertEquals(modifyDNRequest.getControls().length, 2);

    assertNotNull(modifyDNRequest.toLDIFChangeRecord());

    assertNotNull(modifyDNRequest.toLDIF());
    assertTrue(modifyDNRequest.toLDIF().length > 0);

    assertNotNull(modifyDNRequest.toLDIFString());

    assertNotNull(modifyDNRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyDNRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyDNRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the eighth constructor, which takes DN and newRDN objects, a
   * deleteOldRDN flag, a newSuperior DN, and set of controls, using a null
   * newSuperior DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8NullNewSuperior()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest(new DN("ou=People,dc=example,dc=com"),
                             new RDN("ou=Users"), true, null, controls);
    modifyDNRequest = modifyDNRequest.duplicate();

    assertNotNull(modifyDNRequest.getDN());
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    assertNotNull(modifyDNRequest.getNewRDN());
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    assertTrue(modifyDNRequest.deleteOldRDN());

    assertNull(modifyDNRequest.getNewSuperiorDN());

    assertTrue(modifyDNRequest.hasControl());
    assertTrue(modifyDNRequest.hasControl("1.2.3.4"));
    assertNotNull(modifyDNRequest.getControl("1.2.3.4"));
    assertFalse(modifyDNRequest.hasControl("1.2.3.6"));
    assertNull(modifyDNRequest.getControl("1.2.3.6"));
    assertNotNull(modifyDNRequest.getControls());
    assertEquals(modifyDNRequest.getControls().length, 2);

    assertNotNull(modifyDNRequest.toLDIFChangeRecord());

    assertNotNull(modifyDNRequest.toLDIF());
    assertTrue(modifyDNRequest.toLDIF().length > 0);

    assertNotNull(modifyDNRequest.toLDIFString());

    assertNotNull(modifyDNRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    modifyDNRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    modifyDNRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(modifyDNRequest);
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
    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true,
                             "o=example.com");
    assertEquals(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");

    modifyDNRequest.setDN("ou=Persons,dc=example,dc=com");
    assertEquals(modifyDNRequest.getDN(), "ou=Persons,dc=example,dc=com");

    modifyDNRequest.setDN(new DN("ou=Individuals,dc=example,dc=com"));
    assertEquals(modifyDNRequest.getDN(), "ou=Individuals,dc=example,dc=com");

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the {@code getNewRDN} and {@code setNewRDN} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetNewRDN()
         throws Exception
  {
    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true,
                             "o=example.com");
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Users");

    modifyDNRequest.setNewRDN("ou=Persons");
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Persons");

    modifyDNRequest.setNewRDN(new RDN("ou=Individuals"));
    assertEquals(modifyDNRequest.getNewRDN(), "ou=Individuals");

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the {@code deleteOldRDN} and {@code setDeleteOldRDN} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetDeleteOldRDN()
         throws Exception
  {
    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true,
                             "o=example.com");
    assertTrue(modifyDNRequest.deleteOldRDN());

    modifyDNRequest.setDeleteOldRDN(false);
    assertFalse(modifyDNRequest.deleteOldRDN());

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests the {@code getNewSuperiorDN} and {@code setNewSuperiorDN} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetNewSuperiorDN()
         throws Exception
  {
    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true,
                             "o=example.com");
    assertEquals(modifyDNRequest.getNewSuperiorDN(), "o=example.com");

    modifyDNRequest.setNewSuperiorDN("o=example.net");
    assertEquals(modifyDNRequest.getNewSuperiorDN(), "o=example.net");

    modifyDNRequest.setNewSuperiorDN((String) null);
    assertNull(modifyDNRequest.getNewSuperiorDN());

    modifyDNRequest.setNewSuperiorDN(new DN("o=example.org"));
    assertEquals(modifyDNRequest.getNewSuperiorDN(), "o=example.org");

    modifyDNRequest.setNewSuperiorDN((DN) null);
    assertNull(modifyDNRequest.getNewSuperiorDN());

    testEncoding(modifyDNRequest);
  }



  /**
   * Tests to ensure that the encoding for the provided modify DN request is
   * identical when using the stream-based and non-stream-based ASN.1 encoding
   * mechanisms.
   *
   * @param  modifyDNRequest  The modify DN request to be tested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void testEncoding(final ModifyDNRequest modifyDNRequest)
          throws Exception
  {
    ASN1Element protocolOpElement = modifyDNRequest.encodeProtocolOp();

    ASN1Buffer b = new ASN1Buffer();
    modifyDNRequest.writeTo(b);

    assertTrue(Arrays.equals(b.toByteArray(), protocolOpElement.encode()));
  }
}
