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
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.PermissiveModifyRequestControl;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the LDIFModifyChangeRecord class.
 */
public class LDIFModifyChangeRecordTestCase
       extends LDIFTestCase
{
  /**
   * Tests the first constructor with a single modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1SingleModification()
         throws Exception
  {
    Modification[] mods =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    LDIFModifyChangeRecord r =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods);

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getModifications());
    assertEquals(r.getModifications().length, 1);

    ModifyRequest modifyRequest = r.toModifyRequest();
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.MODIFY);

    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    String[] ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

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

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(false);
    assertFalse(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 4);

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(true);
    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

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


    r = r.duplicate();

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getModifications());
    assertEquals(r.getModifications().length, 1);

    modifyRequest = r.toModifyRequest();
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.MODIFY);

    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

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

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(false);
    assertFalse(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 4);

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(true);
    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

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

    assertNotNull(r.getModifications());
    assertEquals(r.getModifications().length, 1);

    modifyRequest = r.toModifyRequest();
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.MODIFY);

    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

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

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(false);
    assertFalse(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 4);

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(true);
    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

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

    assertNotNull(r.getModifications());
    assertEquals(r.getModifications().length, 1);

    modifyRequest = r.toModifyRequest();
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.MODIFY);

    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

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

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(false);
    assertFalse(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 4);

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(true);
    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

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

    assertNotNull(r.getModifications());
    assertEquals(r.getModifications().length, 1);

    modifyRequest = r.toModifyRequest();
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.MODIFY);

    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 6);

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

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(false);
    assertFalse(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(true);
    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

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
         new PermissiveModifyRequestControl(false));

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getModifications());
    assertEquals(r.getModifications().length, 1);

    modifyRequest = r.toModifyRequest();
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.MODIFY);

    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 7);

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

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(false);
    assertFalse(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 6);

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(true);
    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

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
              new PermissiveModifyRequestControl(false)));
  }



  /**
   * Tests the first constructor with multiple modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1MultipleModifications()
         throws Exception
  {
    Modification[] mods =
    {
      new Modification(ModificationType.REPLACE, "description", "foo", "bar"),
      new Modification(ModificationType.ADD, "objectClass", "extensibleObject"),
      new Modification(ModificationType.DELETE, "cn"),
      new Modification(ModificationType.INCREMENT, "intValue", "5")
    };

    LDIFModifyChangeRecord r =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods);

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getModifications());
    assertEquals(r.getModifications().length, 4);

    ModifyRequest modifyRequest = r.toModifyRequest();
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.MODIFY);

    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    String[] ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 14);

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

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(false);
    assertFalse(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 13);

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(true);
    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

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
  }



  /**
   * Tests the first constructor with a {@code null} DN.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullDN()
  {
    Modification[] mods =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    new LDIFModifyChangeRecord(null, mods);
  }



  /**
   * Tests the first constructor with a {@code null} set of modifications.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullModifications()
  {
    new LDIFModifyChangeRecord("dc=example,dc=com", (Modification[]) null);
  }



  /**
   * Tests the first constructor with an empty set of modifications.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1EmptyModifications()
  {
    new LDIFModifyChangeRecord("dc=example,dc=com");
  }



  /**
   * Tests the second constructor with a single modification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2SingleModification()
         throws Exception
  {
    List<Modification> mods = Arrays.asList(
         new Modification(ModificationType.ADD, "description", "foo"));

    LDIFModifyChangeRecord r =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods);

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getModifications());
    assertEquals(r.getModifications().length, 1);

    ModifyRequest modifyRequest = r.toModifyRequest();
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.MODIFY);

    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    String[] ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

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

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(false);
    assertFalse(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 4);

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(true);
    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

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
  }



  /**
   * Tests the second constructor with multiple modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2MultipleModifications()
         throws Exception
  {
    List<Modification> mods = Arrays.asList(
      new Modification(ModificationType.REPLACE, "description", "foo", "bar"),
      new Modification(ModificationType.ADD, "objectClass", "extensibleObject"),
      new Modification(ModificationType.DELETE, "cn"),
      new Modification(ModificationType.INCREMENT, "intValue", "5"));

    LDIFModifyChangeRecord r =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods);

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getModifications());
    assertEquals(r.getModifications().length, 4);

    ModifyRequest modifyRequest = r.toModifyRequest();
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.MODIFY);

    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    String[] ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 14);

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

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(false);
    assertFalse(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 13);

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(true);
    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

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
  }



  /**
   * Tests the second constructor with a {@code null} DN.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NullDN()
  {
    List<Modification> mods = Arrays.asList(
      new Modification(ModificationType.ADD, "description", "foo"));

    new LDIFModifyChangeRecord(null, mods);
  }



  /**
   * Tests the second constructor with a {@code null} set of modifications.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NullModifications()
  {
    new LDIFModifyChangeRecord("dc=example,dc=com", (List<Modification>) null);
  }



  /**
   * Tests the second constructor with an empty set of modifications.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2EmptyModifications()
  {
    new LDIFModifyChangeRecord("dc=example,dc=com",
                               Collections.<Modification>emptyList());
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
    Modification[] mods =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    ModifyRequest modifyRequest = new ModifyRequest("dc=example,dc=com", mods);
    LDIFModifyChangeRecord r = new LDIFModifyChangeRecord(modifyRequest);

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), "dc=example,dc=com");
    assertEquals(r.getParsedDN(), new DN("dc=example,dc=com"));

    assertNotNull(r.getModifications());
    assertEquals(r.getModifications().length, 1);

    modifyRequest = r.toModifyRequest();
    assertEquals(modifyRequest.getDN(), "dc=example,dc=com");

    assertEquals(r.getChangeType(), ChangeType.MODIFY);

    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    String[] ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 5);

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

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(false);
    assertFalse(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

    ldifLines = r.toLDIF();
    assertNotNull(ldifLines);
    assertEquals(ldifLines.length, 4);

    LDIFModifyChangeRecord.setAlwaysIncludeTrailingDash(true);
    assertTrue(LDIFModifyChangeRecord.alwaysIncludeTrailingDash());

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
  }



  /**
   * Tests the third constructor with a {@code null} modify request.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class,
                               NullPointerException.class  })
  public void testConstructor3NullModifyRequest()
  {
    new LDIFModifyChangeRecord((ModifyRequest) null);
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
    Modification[] mods =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    LDIFModifyChangeRecord r = new LDIFModifyChangeRecord("invalid", mods);

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
    Modification[] mods =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    LDIFModifyChangeRecord r =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods);

    assertFalse(r.equals(null));
  }



  /**
   * Tests the {@code equals} method with a the same object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    Modification[] mods =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    LDIFModifyChangeRecord r =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods);

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
    Modification[] mods1 =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    Modification[] mods2 =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    LDIFModifyChangeRecord r1 =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods1);

    LDIFModifyChangeRecord r2 =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods2);

    assertTrue(r1.equals(r2));
  }



  /**
   * Tests the {@code equals} method with different numbers of modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDifferentNumbersOfMods()
         throws Exception
  {
    Modification[] mods1 =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    Modification[] mods2 =
    {
      new Modification(ModificationType.ADD, "description", "foo"),
      new Modification(ModificationType.REPLACE, "o", "Example Corp.")
    };

    LDIFModifyChangeRecord r1 =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods1);

    LDIFModifyChangeRecord r2 =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods2);

    assertFalse(r1.equals(r2));
  }



  /**
   * Tests the {@code equals} method with the same number but non-equivalent
   * modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDifferentMods()
         throws Exception
  {
    Modification[] mods1 =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    Modification[] mods2 =
    {
      new Modification(ModificationType.ADD, "description", "bar")
    };

    LDIFModifyChangeRecord r1 =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods1);

    LDIFModifyChangeRecord r2 =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods2);

    assertFalse(r1.equals(r2));
  }



  /**
   * Tests the {@code equals} method with a change record with an different DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDifferentDN()
         throws Exception
  {
    Modification[] mods1 =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    Modification[] mods2 =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    LDIFModifyChangeRecord r1 =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods1);

    LDIFModifyChangeRecord r2 =
         new LDIFModifyChangeRecord("o=example.com", mods2);

    assertFalse(r1.equals(r2));
  }



  /**
   * Tests the {@code equals} method with a change record with an invalid DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsInvalidDN()
         throws Exception
  {
    Modification[] mods1 =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    Modification[] mods2 =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    LDIFModifyChangeRecord r1 =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods1);

    LDIFModifyChangeRecord r2 =
         new LDIFModifyChangeRecord("invalid", mods2);

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
    Modification[] mods =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    LDIFModifyChangeRecord r =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods);

    assertFalse(r.equals("not change record"));
  }



  /**
   * Tests the {@code equals} method with an object that is a change record but
   * not a modify change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotModifyChangeRecord()
         throws Exception
  {
    Modification[] mods =
    {
      new Modification(ModificationType.ADD, "description", "foo")
    };

    LDIFModifyChangeRecord r1 =
         new LDIFModifyChangeRecord("dc=example,dc=com", mods);

    LDIFDeleteChangeRecord r2 = new LDIFDeleteChangeRecord("dc=example,dc=com");

    assertFalse(r1.equals(r2));
  }
}
