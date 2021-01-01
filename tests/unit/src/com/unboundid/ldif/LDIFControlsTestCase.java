/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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



import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Arrays;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.util.Base64;



/**
 * This class provides a set of test cases for the use of control elements in
 * LDIF change records.
 */
public final class LDIFControlsTestCase
       extends LDIFTestCase
{
  // The controls represented by the LDIF lines.
  private final ArrayList<Control> controls = new ArrayList<Control>(10);

  // The LDIF lines that represent controls.
  private final ArrayList<String> ldifControls = new ArrayList<String>(10);



  /**
   * Performs the necessary initialization for this class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    final File f = createTempFile();
    final FileOutputStream fos = new FileOutputStream(f, false);
    fos.write("hello".getBytes("UTF-8"));
    fos.close();
    final String fileURL = "file://" + f.getAbsolutePath();


    // A control definition that has just an OID.
    ldifControls.add("control: 1.1.1.1");
    controls.add(new Control("1.1.1.1"));

    // A control definition that has an OID and criticality of false.
    ldifControls.add("control: 1.1.1.2 false");
    controls.add(new Control("1.1.1.2", false));

    // A control definition that has an OID and criticality of true, with extra
    // spaces in between the OID and criticality.
    ldifControls.add("control: 1.1.1.3     true");
    controls.add(new Control("1.1.1.3", true));

    // A control definition that has an OID and a raw value with no space after
    // the colon.
    ldifControls.add("control: 1.1.1.4:value1.1.1.4");
    controls.add(new Control("1.1.1.4", false,
         new ASN1OctetString("value1.1.1.4")));

    // A control definition that has an OID, a criticality, and a raw value with
    // a space after the colon.
    ldifControls.add("control: 1.1.1.5 true: value1.1.1.5");
    controls.add(new Control("1.1.1.5", true,
         new ASN1OctetString("value1.1.1.5")));

    // A control definition that has an OID and a base64-encoded value with no
    // space after the colons.
    ldifControls.add("control: 1.1.1.6::" + Base64.encode("value1.1.1.6"));
    controls.add(new Control("1.1.1.6", false,
         new ASN1OctetString("value1.1.1.6")));

    // A control definition that has an OID, a criticality, and a base64-encoded
    // value with a space after the colons.
    ldifControls.add("control: 1.1.1.8 true:: " +
         Base64.encode("value1.1.1.8"));
    controls.add(new Control("1.1.1.8", true,
         new ASN1OctetString("value1.1.1.8")));

    // A control definition that has an OID and URL-specified value with no
    // space after the less-than.
    ldifControls.add("control: 1.1.1.9:<" + fileURL);
    controls.add(new Control("1.1.1.9", false, new ASN1OctetString("hello")));

    // A control definition that has an OID, a criticality, and a URL-specified
    // value with a space after the less-than.
    ldifControls.add("control: 1.1.1.10 false:< " + fileURL);
    controls.add(new Control("1.1.1.10", false, new ASN1OctetString("hello")));
  }



  /**
   * Tests control behavior for an LDIF add change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddChangeRecord()
         throws Exception
  {
    // Decode the add change record from raw strings.
    LDIFChangeRecord r = LDIFReader.decodeChangeRecord(
         generateChangeRecordLines("dc=example,dc=com", "add",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
    assertTrue(r instanceof LDIFAddChangeRecord);
    assertNotNull(r.toString());

    LDIFAddChangeRecord addRecord = (LDIFAddChangeRecord) r;
    assertEquals(addRecord.getControls(), controls);
    assertEquals(addRecord.getEntryToAdd(), new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));


    // Generate an LDIF representation from the add change record and ensure it
    // decodes to the same thing.
    r = LDIFReader.decodeChangeRecord(addRecord.toLDIF());
    assertTrue(r instanceof LDIFAddChangeRecord);
    assertNotNull(r.toString());

    addRecord = (LDIFAddChangeRecord) r;
    assertEquals(addRecord.getControls(), controls);
    assertEquals(addRecord.getEntryToAdd(), new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    // Write the LDIF representation to a file, read it back, and ensure it
    // decodes to the same thing.
    final File ldifFile = createTempFile();
    assertTrue(ldifFile.delete());

    final LDIFWriter writer = new LDIFWriter(ldifFile);
    writer.writeChangeRecord(addRecord);
    writer.close();

    final LDIFReader reader = new LDIFReader(ldifFile);
    r = reader.readChangeRecord();
    assertNull(reader.readLDIFRecord());
    assertTrue(r instanceof LDIFAddChangeRecord);
    assertNotNull(r.toString());

    addRecord = (LDIFAddChangeRecord) r;
    assertEquals(addRecord.getControls(), controls);
    assertEquals(addRecord.getEntryToAdd(), new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    final AddRequest addRequest = addRecord.toAddRequest();
    assertEquals(addRequest.getControlList(), controls);
    assertEquals(addRequest.toEntry(), new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));
  }



  /**
   * Tests control behavior for an LDIF delete change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteChangeRecord()
         throws Exception
  {
    // Decode the delete change record from raw strings.
    LDIFChangeRecord r = LDIFReader.decodeChangeRecord(
         generateChangeRecordLines("dc=example,dc=com", "delete"));
    assertTrue(r instanceof LDIFDeleteChangeRecord);
    assertNotNull(r.toString());

    LDIFDeleteChangeRecord deleteRecord = (LDIFDeleteChangeRecord) r;
    assertEquals(deleteRecord.getControls(), controls);
    assertDNsEqual(deleteRecord.getDN(), "dc=example,dc=com");


    // Generate an LDIF representation from the delete change record and ensure
    // it decodes to the same thing.
    r = LDIFReader.decodeChangeRecord(deleteRecord.toLDIF());
    assertTrue(r instanceof LDIFDeleteChangeRecord);
    assertNotNull(r.toString());

    deleteRecord = (LDIFDeleteChangeRecord) r;
    assertEquals(deleteRecord.getControls(), controls);
    assertDNsEqual(deleteRecord.getDN(), "dc=example,dc=com");

    // Write the LDIF representation to a file, read it back, and ensure it
    // decodes to the same thing.
    final File ldifFile = createTempFile();
    assertTrue(ldifFile.delete());

    final LDIFWriter writer = new LDIFWriter(ldifFile);
    writer.writeChangeRecord(deleteRecord);
    writer.close();

    final LDIFReader reader = new LDIFReader(ldifFile);
    r = reader.readChangeRecord();
    assertNull(reader.readLDIFRecord());
    assertTrue(r instanceof LDIFDeleteChangeRecord);
    assertNotNull(r.toString());

    deleteRecord = (LDIFDeleteChangeRecord) r;
    assertEquals(deleteRecord.getControls(), controls);
    assertDNsEqual(deleteRecord.getDN(), "dc=example,dc=com");

    final DeleteRequest deleteRequest = deleteRecord.toDeleteRequest();
    assertEquals(deleteRequest.getControlList(), controls);
    assertDNsEqual(deleteRequest.getDN(), "dc=example,dc=com");
  }



  /**
   * Tests control behavior for an LDIF modify change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyChangeRecord()
         throws Exception
  {
    // Decode the modify change record from raw strings.
    LDIFChangeRecord r = LDIFReader.decodeChangeRecord(
         generateChangeRecordLines("dc=example,dc=com", "modify",
              "replace: description",
              "description: foo"));
    assertTrue(r instanceof LDIFModifyChangeRecord);
    assertNotNull(r.toString());

    LDIFModifyChangeRecord modifyRecord = (LDIFModifyChangeRecord) r;
    assertEquals(modifyRecord.getControls(), controls);
    assertDNsEqual(modifyRecord.getDN(), "dc=example,dc=com");
    assertEquals(Arrays.asList(modifyRecord.getModifications()),
         Arrays.asList(new Modification(ModificationType.REPLACE, "description",
              "foo")));


    // Generate an LDIF representation from the modify change record and ensure
    // it decodes to the same thing.
    r = LDIFReader.decodeChangeRecord(modifyRecord.toLDIF());
    assertTrue(r instanceof LDIFModifyChangeRecord);
    assertNotNull(r.toString());

    modifyRecord = (LDIFModifyChangeRecord) r;
    assertEquals(modifyRecord.getControls(), controls);
    assertDNsEqual(modifyRecord.getDN(), "dc=example,dc=com");
    assertEquals(Arrays.asList(modifyRecord.getModifications()),
         Arrays.asList(new Modification(ModificationType.REPLACE, "description",
              "foo")));

    // Write the LDIF representation to a file, read it back, and ensure it
    // decodes to the same thing.
    final File ldifFile = createTempFile();
    assertTrue(ldifFile.delete());

    final LDIFWriter writer = new LDIFWriter(ldifFile);
    writer.writeChangeRecord(modifyRecord);
    writer.close();

    final LDIFReader reader = new LDIFReader(ldifFile);
    r = reader.readChangeRecord();
    assertNull(reader.readLDIFRecord());
    assertTrue(r instanceof LDIFModifyChangeRecord);
    assertNotNull(r.toString());

    modifyRecord = (LDIFModifyChangeRecord) r;
    assertEquals(modifyRecord.getControls(), controls);
    assertDNsEqual(modifyRecord.getDN(), "dc=example,dc=com");
    assertEquals(Arrays.asList(modifyRecord.getModifications()),
         Arrays.asList(new Modification(ModificationType.REPLACE, "description",
              "foo")));

    final ModifyRequest modifyRequest = modifyRecord.toModifyRequest();
    assertEquals(modifyRequest.getControlList(), controls);
    assertDNsEqual(modifyRequest.getDN(), "dc=example,dc=com");
    assertEquals(modifyRequest.getModifications(),
         Arrays.asList(new Modification(ModificationType.REPLACE, "description",
              "foo")));
  }



  /**
   * Tests control behavior for an LDIF modify DN change record using a
   * changetype of moddn.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNChangeRecordAsModDN()
         throws Exception
  {
    // Decode the modify DN change record from raw strings.
    LDIFChangeRecord r = LDIFReader.decodeChangeRecord(
         generateChangeRecordLines("ou=People,dc=example,dc=com", "moddn",
              "newrdn: ou=Users",
              "deleteoldrdn: 1"));
    assertTrue(r instanceof LDIFModifyDNChangeRecord);
    assertNotNull(r.toString());

    LDIFModifyDNChangeRecord modifyDNRecord = (LDIFModifyDNChangeRecord) r;
    assertEquals(modifyDNRecord.getControls(), controls);
    assertDNsEqual(modifyDNRecord.getDN(), "ou=People,dc=example,dc=com");
    assertEquals(new RDN(modifyDNRecord.getNewRDN()), new RDN("ou=Users"));
    assertTrue(modifyDNRecord.deleteOldRDN());
    assertNull(modifyDNRecord.getNewSuperiorDN());


    // Generate an LDIF representation from the modify DN change record and
    // ensure it decodes to the same thing.
    r = LDIFReader.decodeChangeRecord(modifyDNRecord.toLDIF());
    assertTrue(r instanceof LDIFModifyDNChangeRecord);
    assertNotNull(r.toString());

    modifyDNRecord = (LDIFModifyDNChangeRecord) r;
    assertEquals(modifyDNRecord.getControls(), controls);
    assertDNsEqual(modifyDNRecord.getDN(), "ou=People,dc=example,dc=com");
    assertEquals(new RDN(modifyDNRecord.getNewRDN()), new RDN("ou=Users"));
    assertTrue(modifyDNRecord.deleteOldRDN());
    assertNull(modifyDNRecord.getNewSuperiorDN());

    // Write the LDIF representation to a file, read it back, and ensure it
    // decodes to the same thing.
    final File ldifFile = createTempFile();
    assertTrue(ldifFile.delete());

    final LDIFWriter writer = new LDIFWriter(ldifFile);
    writer.writeChangeRecord(modifyDNRecord);
    writer.close();

    final LDIFReader reader = new LDIFReader(ldifFile);
    r = reader.readChangeRecord();
    assertNull(reader.readLDIFRecord());
    assertTrue(r instanceof LDIFModifyDNChangeRecord);
    assertNotNull(r.toString());

    modifyDNRecord = (LDIFModifyDNChangeRecord) r;
    assertEquals(modifyDNRecord.getControls(), controls);
    assertDNsEqual(modifyDNRecord.getDN(), "ou=People,dc=example,dc=com");
    assertEquals(new RDN(modifyDNRecord.getNewRDN()), new RDN("ou=Users"));
    assertTrue(modifyDNRecord.deleteOldRDN());
    assertNull(modifyDNRecord.getNewSuperiorDN());

    final ModifyDNRequest modifyDNRequest = modifyDNRecord.toModifyDNRequest();
    assertEquals(modifyDNRequest.getControlList(), controls);
    assertDNsEqual(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");
    assertEquals(new RDN(modifyDNRequest.getNewRDN()), new RDN("ou=Users"));
    assertTrue(modifyDNRequest.deleteOldRDN());
    assertNull(modifyDNRequest.getNewSuperiorDN());
  }



  /**
   * Tests control behavior for an LDIF modify DN change record using a
   * changetype of modrdn.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNChangeRecordAsModRDN()
         throws Exception
  {
    // Decode the modify DN change record from raw strings.
    LDIFChangeRecord r = LDIFReader.decodeChangeRecord(
         generateChangeRecordLines("ou=People,dc=example,dc=com", "modrdn",
              "newrdn: ou=Users",
              "deleteoldrdn: 1",
              "newsuperior: o=example.com"));
    assertTrue(r instanceof LDIFModifyDNChangeRecord);
    assertNotNull(r.toString());

    LDIFModifyDNChangeRecord modifyDNRecord = (LDIFModifyDNChangeRecord) r;
    assertEquals(modifyDNRecord.getControls(), controls);
    assertDNsEqual(modifyDNRecord.getDN(), "ou=People,dc=example,dc=com");
    assertEquals(new RDN(modifyDNRecord.getNewRDN()), new RDN("ou=Users"));
    assertTrue(modifyDNRecord.deleteOldRDN());
    assertDNsEqual(modifyDNRecord.getNewSuperiorDN(), "o=example.com");


    // Generate an LDIF representation from the modify DN change record and
    // ensure it decodes to the same thing.
    r = LDIFReader.decodeChangeRecord(modifyDNRecord.toLDIF());
    assertTrue(r instanceof LDIFModifyDNChangeRecord);
    assertNotNull(r.toString());

    modifyDNRecord = (LDIFModifyDNChangeRecord) r;
    assertEquals(modifyDNRecord.getControls(), controls);
    assertDNsEqual(modifyDNRecord.getDN(), "ou=People,dc=example,dc=com");
    assertEquals(new RDN(modifyDNRecord.getNewRDN()), new RDN("ou=Users"));
    assertTrue(modifyDNRecord.deleteOldRDN());
    assertDNsEqual(modifyDNRecord.getNewSuperiorDN(), "o=example.com");

    // Write the LDIF representation to a file, read it back, and ensure it
    // decodes to the same thing.
    final File ldifFile = createTempFile();
    assertTrue(ldifFile.delete());

    final LDIFWriter writer = new LDIFWriter(ldifFile);
    writer.writeChangeRecord(modifyDNRecord);
    writer.close();

    final LDIFReader reader = new LDIFReader(ldifFile);
    r = reader.readChangeRecord();
    assertNull(reader.readLDIFRecord());
    assertTrue(r instanceof LDIFModifyDNChangeRecord);
    assertNotNull(r.toString());

    modifyDNRecord = (LDIFModifyDNChangeRecord) r;
    assertEquals(modifyDNRecord.getControls(), controls);
    assertDNsEqual(modifyDNRecord.getDN(), "ou=People,dc=example,dc=com");
    assertEquals(new RDN(modifyDNRecord.getNewRDN()), new RDN("ou=Users"));
    assertTrue(modifyDNRecord.deleteOldRDN());
    assertDNsEqual(modifyDNRecord.getNewSuperiorDN(), "o=example.com");

    final ModifyDNRequest modifyDNRequest = modifyDNRecord.toModifyDNRequest();
    assertEquals(modifyDNRequest.getControlList(), controls);
    assertDNsEqual(modifyDNRequest.getDN(), "ou=People,dc=example,dc=com");
    assertEquals(new RDN(modifyDNRequest.getNewRDN()), new RDN("ou=Users"));
    assertTrue(modifyDNRequest.deleteOldRDN());
    assertDNsEqual(modifyDNRequest.getNewSuperiorDN(), "o=example.com");
  }



  /**
   * Tests to ensure that a base64-encoded control definition is acceptable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBase64EncodedControl()
         throws Exception
  {
    final LDIFChangeRecord r = LDIFReader.decodeChangeRecord(
         "dn: dc=example,dc=com",
         "control:: " + Base64.encode("1.2.3.4"),
         "changetype: delete");

    assertNotNull(r);
    assertTrue(r instanceof LDIFDeleteChangeRecord);

    assertNotNull(r.getControls());
    assertEquals(r.getControls(),
         Arrays.asList(new Control("1.2.3.4")));
  }



  /**
   * Tests to ensure that a malformed base64-encoded control definition is not
   * acceptable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testMalformedBase64EncodedControl()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(
         "dn: dc=example,dc=com",
         "control:: malformed.base64",
         "changetype: delete");
  }



  /**
   * Tests the behavior when trying to decode a control with no content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEmptyControlNoTrailingSpace()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(
         "dn: dc=example,dc=com",
         "control:",
         "changetype: delete");
  }



  /**
   * Tests the behavior when trying to decode a control with no content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeEmptyControlWithTrailingSpace()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(
         "dn: dc=example,dc=com",
         "control: ",
         "changetype: delete");
  }



  /**
   * Tests the behavior when trying to decode a control with an invalid
   * criticality.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeControlInvalidCriticality()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(
         "dn: dc=example,dc=com",
         "control: 1.2.3.4 invalid",
         "changetype: delete");
  }



  /**
   * Tests the behavior when trying to decode a control with a malformed
   * base64-encoded value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeControlMalformedBase64Value()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(
         "dn: dc=example,dc=com",
         "control: 1.2.3.4:: this.is.malformed",
         "changetype: delete");
  }



  /**
   * Tests the behavior when trying to decode a control with an empty raw value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeControlEmptyRawValue()
         throws Exception
  {
    final LDIFChangeRecord r = LDIFReader.decodeChangeRecord(
         "dn: dc=example,dc=com",
         "control: 1.2.3.4: ",
         "changetype: delete");

    assertNotNull(r);
    assertTrue(r instanceof LDIFDeleteChangeRecord);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().size(), 1);
    assertEquals(r.getControls().get(0),
         new Control("1.2.3.4", false, new ASN1OctetString()));
  }



  /**
   * Tests the behavior when trying to decode a control with an empty
   * base64-encoded value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeControlEmptyBase64Value()
         throws Exception
  {
    final LDIFChangeRecord r = LDIFReader.decodeChangeRecord(
         "dn: dc=example,dc=com",
         "control: 1.2.3.4:: ",
         "changetype: delete");

    assertNotNull(r);
    assertTrue(r instanceof LDIFDeleteChangeRecord);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().size(), 1);
    assertEquals(r.getControls().get(0),
         new Control("1.2.3.4", false, new ASN1OctetString()));
  }



  /**
   * Tests the behavior when trying to decode a control with an empty
   * value retrieved via URL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeControlEmptyValueFromURL()
         throws Exception
  {
    final File f = createTempFile();
    assertEquals(f.length(), 0L);

    final LDIFChangeRecord r = LDIFReader.decodeChangeRecord(
         "dn: dc=example,dc=com",
         "control: 1.2.3.4:< file://" + f.getAbsolutePath(),
         "changetype: delete");

    assertNotNull(r);
    assertTrue(r instanceof LDIFDeleteChangeRecord);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().size(), 1);
    assertEquals(r.getControls().get(0),
         new Control("1.2.3.4", false, new ASN1OctetString()));
  }



  /**
   * Tests the behavior when trying to decode a control with an empty
   * value that references a malformed URL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeControlValueFromMalformedURL()
         throws Exception
  {
    LDIFReader.decodeChangeRecord(
         "dn: dc=example,dc=com",
         "control: 1.2.3.4:< malformed://url",
         "changetype: delete");
  }



  /**
   * Tests the behavior when trying to decode a control with an empty
   * value that references a URL to a file that doesn't exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDIFException.class })
  public void testDecodeControlValueFromNonexistentURL()
         throws Exception
  {
    final File f = createTempFile();
    assertTrue(f.delete());

    LDIFReader.decodeChangeRecord(
         "dn: dc=example,dc=com",
         "control: 1.2.3.4:< file://" + f.getAbsolutePath(),
         "changetype: delete");
  }



  /**
   * Creates a string array that represents an LDIF change record that includes
   * all of the controls plus the specified information.
   *
   * @param  dn           The DN for the LDIF change record.
   * @param  changeType   The changetype for the LDIF change record.
   * @param  changeLines  The lines that comprise the remainder of the LDIF
   *                      change record (everything after the changetype line).
   *
   * @return  The array containing the generated change record lines.
   */
  private String[] generateChangeRecordLines(final String dn,
                                             final String changeType,
                                             final String... changeLines)
  {
    final ArrayList<String> lines =
         new ArrayList<String>(12 + changeLines.length);
    lines.add("dn: " + dn);

    for (final String s : ldifControls)
    {
      lines.add(s);
    }

    lines.add("changetype: " + changeType);
    lines.addAll(Arrays.asList(changeLines));

    final String[] lineArray = new String[lines.size()];
    return lines.toArray(lineArray);
  }
}
