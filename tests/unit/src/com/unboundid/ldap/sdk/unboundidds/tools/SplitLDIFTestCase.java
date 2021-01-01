/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.PassphraseEncryptedInputStream;
import com.unboundid.util.PasswordReader;



/**
 * This class provides a set of test cases to cover the SplitLDIF tool.
 */
public final class SplitLDIFTestCase
       extends LDAPSDKTestCase
{
  // Pre-created files that can be used for testing.
  private File emptyFile = null;
  private File onlyEntriesOutsideSplitFile = null;
  private File onlySplitBaseEntryFile = null;
  private File flatDITFile = null;
  private File branchedDITFile = null;

  // Test schema files.
  private File schemaFile = null;
  private File schemaDir = null;



  /**
   * Pre-creates a number of files that can be used for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    emptyFile = createTempFile();

    onlyEntriesOutsideSplitFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");

    onlySplitBaseEntryFile = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    flatDITFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=aaron.adams,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: aaron.adams",
         "givenName: Aaron",
         "sn: Adams",
         "cn: Aaron Adams",
         "",
         "dn: uid=brenda.brown,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: brenda.brown",
         "givenName: Brenda",
         "sn: Brown",
         "cn: Brenda Brown",
         "",
         "dn: uid=chris.connors,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: chris.connors",
         "givenName: Chris",
         "givenName: Christopher",
         "sn: Connors",
         "cn: Chris Connors",
         "",
         "dn: uid=denise.daniels,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: denise.daniels",
         "givenName: Denise",
         "sn: Daniels",
         "cn: Denise Daniels",
         "",
         "dn: uid=eugene.edwards,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: eugene.edwards",
         "givenName: Eugene",
         "sn: Edwards",
         "cn: Eugene Edwards",
         "",
         "dn: uid=florence.flanders,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: florence.flanders",
         "givenName: Florence",
         "sn: Flanders",
         "cn: Florence Flanders",
         "",
         "dn: uid=george.graham,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: george.graham",
         "givenName: George",
         "sn: Graham",
         "cn: George Graham",
         "",
         "dn: uid=helen.hawking,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: helen.hawking",
         "givenName: Helen",
         "sn: Hawking",
         "cn: Helen Hawking",
         "",
         "dn: uid=ivan.irving,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: ivan.irving",
         "givenName: Ivan",
         "sn: Irving",
         "cn: Ivan Irving",
         "",
         "dn: uid=jennifer.jensen,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: jennifer.jensen",
         "givenName: Jennifer",
         "sn: Jensen",
         "cn: Jennifer Jensen",
         "",
         "dn: uid=kurt.kline,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: kurt.kline",
         "givenName: Kurt",
         "sn: Kline",
         "cn: Kurt Kline",
         "",
         "dn: uid=laura.larson,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: laura.larson",
         "givenName: Laura",
         "sn: Larson",
         "cn: Laura Larson",
         "",
         "dn: uid=marvin.murphy,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: marvin.murphy",
         "givenName: Marvin",
         "sn: Murphy",
         "cn: Marvin Murphy",
         "",
         "dn: uid=nancy.nessman,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: nancy.nessman",
         "givenName: Nancy",
         "sn: Nessman",
         "cn: Nancy Nessman",
         "",
         "dn: uid=orville.owens,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: orville.owens",
         "givenName: Orville",
         "sn: Owens",
         "cn: Orville Owens",
         "",
         "dn: uid=penny.parker,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: penny.parker",
         "givenName: Penny",
         "sn: Parker",
         "cn: Penny Parker",
         "",
         "dn: uid=quentin.quinn,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: quentin.quinn",
         "givenName: Quentin",
         "sn: Quinn",
         "cn: Quentin Quinn",
         "",
         "dn: uid=rosy.roth,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: rosy.roth",
         "givenName: Rosy",
         "sn: Roth",
         "cn: Rosy Roth",
         "",
         "dn: uid=sam.sanderson,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: sam.sanderson",
         "givenName: Sam",
         "givenName: Samuel",
         "sn: Sanderson",
         "cn: Sam Sanderson",
         "",
         "dn: uid=tara.thomas,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: tara.thomas",
         "givenName: Tara",
         "sn: Thomas",
         "cn: Tara Thomas",
         "",
         "dn: uid=upton.urban,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: upton.urban",
         "givenName: Upton",
         "sn: Urban",
         "cn: Upton Urban",
         "",
         "dn: uid=vera.valdez,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: vera.valdez",
         "givenName: Vera",
         "sn: Valdez",
         "cn: Vera Valdez",
         "",
         "dn: uid=walter.williams,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: walter.williams",
         "givenName: Walter",
         "sn: Williams",
         "cn: Walter Williams",
         "",
         "dn: uid=xena.xavier,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: xena.xavier",
         "givenName: Xena",
         "sn: Xavier",
         "cn: Xena Xavier",
         "",
         "dn: uid=yadier.yamamoto,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: yadier.yamamoto",
         "givenName: Yadier",
         "sn: Yamamoto",
         "cn: Yadier Yamamoto",
         "",
         "dn: uid=zelda.zimmerman,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: zelda.zimmerman",
         "givenName: Zelda",
         "sn: Zimmerman",
         "cn: Zelda Zimmerman");

    branchedDITFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=aaron.adams,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: aaron.adams",
         "givenName: Aaron",
         "sn: Adams",
         "cn: Aaron Adams",
         "",
         "dn: ou=Org A,uid=aaron.adams,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org A",
         "",
         "dn: uid=brenda.brown,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: brenda.brown",
         "givenName: Brenda",
         "sn: Brown",
         "cn: Brenda Brown",
         "",
         "dn: ou=Org B,uid=brenda.brown,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org B",
         "",
         "dn: uid=chris.connors,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: chris.connors",
         "givenName: Chris",
         "sn: Connors",
         "cn: Chris Connors",
         "",
         "dn: ou=Org C,uid=chris.connors,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org C",
         "",
         "dn: uid=denise.daniels,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: denise.daniels",
         "givenName: Denise",
         "sn: Daniels",
         "cn: Denise Daniels",
         "",
         "dn: ou=Org D,uid=denise.daniels,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org D",
         "",
         "dn: uid=eugene.edwards,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: eugene.edwards",
         "givenName: Eugene",
         "sn: Edwards",
         "cn: Eugene Edwards",
         "",
         "dn: ou=Org E,uid=eugene.edwards,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org E",
         "",
         "dn: uid=florence.flanders,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: florence.flanders",
         "givenName: Florence",
         "sn: Flanders",
         "cn: Florence Flanders",
         "",
         "dn: ou=Org F,uid=florence.flanders,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org F",
         "",
         "dn: uid=george.graham,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: george.graham",
         "givenName: George",
         "sn: Graham",
         "cn: George Graham",
         "",
         "dn: ou=Org G,uid=george.graham,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org G",
         "",
         "dn: uid=helen.hawking,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: helen.hawking",
         "givenName: Helen",
         "sn: Hawking",
         "cn: Helen Hawking",
         "",
         "dn: ou=Org H,uid=helen.hawking,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org H",
         "",
         "dn: uid=ivan.irving,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: ivan.irving",
         "givenName: Ivan",
         "sn: Irving",
         "cn: Ivan Irving",
         "",
         "dn: ou=Org I,uid=ivan.irving,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org I",
         "",
         "dn: uid=jennifer.jensen,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: jennifer.jensen",
         "givenName: Jennifer",
         "sn: Jensen",
         "cn: Jennifer Jensen",
         "",
         "dn: ou=Org J,uid=jennifer.jensen,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org J",
         "",
         "dn: uid=kurt.kline,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: kurt.kline",
         "givenName: Kurt",
         "sn: Kline",
         "cn: Kurt Kline",
         "",
         "dn: ou=Org K,uid=kurt.kline,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org K",
         "",
         "dn: uid=laura.larson,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: laura.larson",
         "givenName: Laura",
         "sn: Larson",
         "cn: Laura Larson",
         "",
         "dn: ou=Org L,uid=laura.larson,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org L",
         "",
         "dn: uid=marvin.murphy,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: marvin.murphy",
         "givenName: Marvin",
         "sn: Murphy",
         "cn: Marvin Murphy",
         "",
         "dn: ou=Org M,uid=marvin.murphy,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org M",
         "",
         "dn: uid=nancy.nessman,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: nancy.nessman",
         "givenName: Nancy",
         "sn: Nessman",
         "cn: Nancy Nessman",
         "",
         "dn: ou=Org N,uid=nancy.nessman,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org N",
         "",
         "dn: uid=orville.owens,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: orville.owens",
         "givenName: Orville",
         "sn: Owens",
         "cn: Orville Owens",
         "",
         "dn: ou=Org O,uid=orville.owens,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org O",
         "",
         "dn: uid=penny.parker,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: penny.parker",
         "givenName: Penny",
         "sn: Parker",
         "cn: Penny Parker",
         "",
         "dn: ou=Org P,uid=penny.parker,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org P",
         "",
         "dn: uid=quentin.quinn,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: quentin.quinn",
         "givenName: Quentin",
         "sn: Quinn",
         "cn: Quentin Quinn",
         "",
         "dn: ou=Org Q,uid=quentin.quinn,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org Q",
         "",
         "dn: uid=rosy.roth,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: rosy.roth",
         "givenName: Rosy",
         "sn: Roth",
         "cn: Rosy Roth",
         "",
         "dn: ou=Org R,uid=rosy.roth,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org R",
         "",
         "dn: uid=sam.sanderson,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: sam.sanderson",
         "givenName: Sam",
         "sn: Sanderson",
         "cn: Sam Sanderson",
         "",
         "dn: ou=Org S,uid=sam.sanderson,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org S",
         "",
         "dn: uid=tara.thomas,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: tara.thomas",
         "givenName: Tara",
         "sn: Thomas",
         "cn: Tara Thomas",
         "",
         "dn: ou=Org T,uid=tara.thomas,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org T",
         "",
         "dn: uid=upton.urban,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: upton.urban",
         "givenName: Upton",
         "sn: Urban",
         "cn: Upton Urban",
         "",
         "dn: ou=Org U,uid=upton.urban,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org U",
         "",
         "dn: uid=vera.valdez,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: vera.valdez",
         "givenName: Vera",
         "sn: Valdez",
         "cn: Vera Valdez",
         "",
         "dn: ou=Org V,uid=vera.valdez,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org V",
         "",
         "dn: uid=walter.williams,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: walter.williams",
         "givenName: Walter",
         "sn: Williams",
         "cn: Walter Williams",
         "",
         "dn: ou=Org W,uid=walter.williams,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org W",
         "",
         "dn: uid=xena.xavier,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: xena.xavier",
         "givenName: Xena",
         "sn: Xavier",
         "cn: Xena Xavier",
         "",
         "dn: ou=Org X,uid=xena.xavier,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org X",
         "",
         "dn: uid=yadier.yamamoto,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: yadier.yamamoto",
         "givenName: Yadier",
         "sn: Yamamoto",
         "cn: Yadier Yamamoto",
         "",
         "dn: ou=Org Y,uid=yadier.yamamoto,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org Y",
         "",
         "dn: uid=zelda.zimmerman,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: zelda.zimmerman",
         "givenName: Zelda",
         "sn: Zimmerman",
         "cn: Zelda Zimmerman",
         "",
         "dn: ou=Org Z,uid=zelda.zimmerman,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Org Z");

    final Schema defaultSchema = Schema.getDefaultStandardSchema();
    schemaFile = createTempFile(defaultSchema.getSchemaEntry().toLDIF());

    schemaDir = createTempDir();

    final LDIFWriter atWriter = new LDIFWriter(
         schemaDir.getAbsolutePath() + File.separator + "01-at.ldif");
    atWriter.writeEntry(new Entry("cn=schema",
         new Attribute("objectClass", "top", "ldapSubEntry", "subschema"),
         new Attribute("cn", "schema"),
         defaultSchema.getSchemaEntry().getAttribute("attributeTypes")));
    atWriter.close();

    final LDIFWriter ocWriter = new LDIFWriter(
         schemaDir.getAbsolutePath() + File.separator + "02-oc.ldif");
    ocWriter.writeEntry(new Entry("cn=schema",
         new Attribute("objectClass", "top", "ldapSubEntry", "subschema"),
         new Attribute("cn", "schema"),
         defaultSchema.getSchemaEntry().getAttribute("objectClasses")));
    ocWriter.close();
  }



  /**
   * Provides basic test coverage for the SplitLDIF tool methods that can be
   * covered without running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicMethods()
         throws Exception
  {
    final SplitLDIF tool = new SplitLDIF(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "split-ldif");

    assertNotNull(tool.getToolDescription());

    assertNotNull(tool.getToolVersion());
    assertEquals(tool.getToolVersion(), Version.NUMERIC_VERSION_STRING);

    assertTrue(tool.supportsInteractiveMode());

    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());
  }



  /**
   * Provides test coverage for the SplitLDIF tool when simply used to obtain
   * usage information.  This will be general usage information for the tool
   * when no subcommand was provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneralUsage()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode rc = SplitLDIF.main(out, out, "--help");
    assertEquals(rc, ResultCode.SUCCESS);
    assertTrue(out.toByteArray().length > 0);
  }



  /**
   * Provides test coverage for the SplitLDIF tool when simply used to obtain
   * usage information for a specific subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubcommandUsage()
         throws Exception
  {
    for (final String subcommand :
         Arrays.asList("split-using-hash-on-rdn",
              "split-using-hash-on-attribute", "split-using-fewest-entries",
              "split-using-filter"))
    {
      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      final ResultCode rc = SplitLDIF.main(out, out, subcommand, "--help");
      assertEquals(rc, ResultCode.SUCCESS);
      assertTrue(out.toByteArray().length > 0);
    }
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-rdn
   * subcommand with an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnRDNEmptyFile()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", emptyFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaFile.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 0);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-rdn
   * subcommand with a file containing only entries outside the split when not
   * using any options that would cause those entries to be written.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnRDNOnlyEntriesOutsideSplitNoneWritten()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 0);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-rdn
   * subcommand with a file containing only entries outside the split when
   * those entries should only be written into a dedicated set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnRDNOnlyEntriesOutsideSplitIntoDedicatedSet()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 1);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-rdn
   * subcommand with a file containing only entries outside the split when
   * those entries should only be written into all sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnRDNOnlyEntriesOutsideSplitIntoAllSets()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 4);

    assertEquals(countEntries(outputDir, "output.ldif.set1"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 2);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-rdn
   * subcommand with a file containing only the split base entry itself, which
   * should be written into all sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnRDNOnlySplitBaseEntry()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 4);

    assertEquals(countEntries(outputDir, "output.ldif.set1"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 1);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-rdn
   * subcommand with a pair of files, the first containing only entries outside
   * the split and the second containing only the split base entry, when entries
   * outside the split should be written to a dedicated file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnRDNOnlyOutsideAndSplitBaseEntrySeparateSets()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set1"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 1);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-rdn
   * subcommand with a pair of files, the first containing only entries outside
   * the split and the second containing only the split base entry, when entries
   * outside the split should be written to all sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnRDNOnlyOutsideAndSplitBaseEntryAllSets()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 4);

    assertEquals(countEntries(outputDir, "output.ldif.set1"), 3);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 3);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 3);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 3);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-rdn
   * subcommand with an LDIF file that contains entries outside the split, the
   * split base entry, and entries immediately below the split base entry.  The
   * entries outside the split will be added both to a dedicated set and to all
   * split sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnRDNFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", flatDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count = countEntries(outputDir, "output.ldif.set1");
    final int set2Count = countEntries(outputDir, "output.ldif.set2");
    final int set3Count = countEntries(outputDir, "output.ldif.set3");
    final int set4Count = countEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-rdn
   * subcommand with an LDIF file that contains entries outside the split, the
   * split base entry, entries immediately below the split base entry, and
   * additional subordinate entries.  The entries outside the split will be only
   * to a dedicated set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnRDNNonFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", branchedDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the split base entry, and then the 26 entries below the split
    // base will be split individually, and the 26 subordinate entries should
    // always go to the same set as their parents, for a total of 56 entries.
    final Map<DN,Entry> set1Map = readEntries(outputDir, "output.ldif.set1");
    final Map<DN,Entry> set2Map = readEntries(outputDir, "output.ldif.set2");
    final Map<DN,Entry> set3Map = readEntries(outputDir, "output.ldif.set3");
    final Map<DN,Entry> set4Map = readEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Map.size() > 1);
    assertTrue(set2Map.size() > 1);
    assertTrue(set3Map.size() > 1);
    assertTrue(set4Map.size() > 1);

    assertEquals(
         (set1Map.size() + set2Map.size() + set3Map.size() + set4Map.size()),
         56);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-rdn
   * subcommand with an LDIF file that contains malformed entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnRDNMalformedEntries()
         throws Exception
  {
    final File outputDir = createTempDir();

    final File sourceFile = new File(outputDir, "source.ldif");
    final PrintWriter w = new PrintWriter(sourceFile);
    w.println("dn: malformed DN");
    w.println("objectClass: top");
    w.println("objectClass: domain");
    w.println("dc: malformed DN");
    w.println("");
    w.println("dn: ou=malformed attribute,dc=malformed DN");
    w.println("objectClass: top");
    w.println("objectClass: organizationalUnit");
    w.println("malformed");
    w.println("");
    w.close();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", sourceFile.getAbsolutePath(),
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numSets", "4");
    assertEquals(rc, ResultCode.LOCAL_ERROR);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 2); // Source and errors.

    assertTrue(new File(outputDir, "source.ldif.errors").exists());
    assertTrue(new File(outputDir, "source.ldif.errors").length() > 0L);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeEmptyFile()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", emptyFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaFile.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--attributeName", "givenName",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 0);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with a file containing only entries outside the split when not
   * using any options that would cause those entries to be written.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeOnlyEntriesOutsideSplitNoneWritten()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--attributeName", "givenName",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 0);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with a file containing only entries outside the split when
   * those entries should only be written into a dedicated set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeOnlyEntriesOutsideSplitIntoDedicatedSet()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--attributeName", "givenName",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 1);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with a file containing only entries outside the split when
   * those entries should only be written into all sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeOnlyEntriesOutsideSplitIntoAllSets()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--attributeName", "givenName",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 4);

    assertEquals(countEntries(outputDir, "output.ldif.set1"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 2);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with a file containing only the split base entry itself, which
   * should be written into all sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeOnlySplitBaseEntry()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--attributeName", "givenName",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 4);

    assertEquals(countEntries(outputDir, "output.ldif.set1"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 1);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with a pair of files, the first containing only entries outside
   * the split and the second containing only the split base entry, when entries
   * outside the split should be written to a dedicated file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeOnlyOutsideAndSplitBaseEntrySeparateSets()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--attributeName", "givenName",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set1"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 1);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with a pair of files, the first containing only entries outside
   * the split and the second containing only the split base entry, when entries
   * outside the split should be written to all sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeOnlyOutsideAndSplitBaseEntryAllSets()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--attributeName", "givenName",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 4);

    assertEquals(countEntries(outputDir, "output.ldif.set1"), 3);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 3);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 3);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 3);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with an LDIF file that contains entries outside the split, the
   * split base entry, and entries immediately below the split base entry.  The
   * entries outside the split will be added both to a dedicated set and to all
   * split sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", flatDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--attributeName", "givenName",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count = countEntries(outputDir, "output.ldif.set1");
    final int set2Count = countEntries(outputDir, "output.ldif.set2");
    final int set3Count = countEntries(outputDir, "output.ldif.set3");
    final int set4Count = countEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with an LDIF file that contains entries outside the split, the
   * split base entry, and entries immediately below the split base entry.  The
   * entries outside the split will be added both to a dedicated set and to all
   * split sets.  The --assumeFlatDIT option should be used, and should produce
   * behavior that is identical to the behavior without that option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeFlatDITAssumeFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();
    final File passphraseFile = createTempFile("passphrase");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", flatDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--compressTarget",
         "--encryptTarget",
         "--encryptionPassphraseFile", passphraseFile.getAbsolutePath(),
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--attributeName", "givenName",
         "--numSets", "4",
         "--assumeFlatDIT");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(
         readEntries(outputDir, "output.ldif.outside-split", true, true,
              true).size(),
         2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count =
         readEntries(outputDir, "output.ldif.set1", true, true, true).size();
    final int set2Count =
         readEntries(outputDir, "output.ldif.set2", true, true, true).size();
    final int set3Count =
         readEntries(outputDir, "output.ldif.set3", true, true, true).size();
    final int set4Count =
         readEntries(outputDir, "output.ldif.set4", true, true, true).size();

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with an LDIF file that contains entries outside the split, the
   * split base entry, and entries immediately below the split base entry.  The
   * entries outside the split will be added both to a dedicated set and to all
   * split sets.  All values for the target attribute will be used rather than
   * just the first.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeFlatDITUseAllValues()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", flatDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--attributeName", "givenName",
         "--numSets", "4",
         "--useAllValues");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count = countEntries(outputDir, "output.ldif.set1");
    final int set2Count = countEntries(outputDir, "output.ldif.set2");
    final int set3Count = countEntries(outputDir, "output.ldif.set3");
    final int set4Count = countEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with an LDIF file that contains entries outside the split, the
   * split base entry, and entries immediately below the split base entry.  The
   * entries outside the split will be added both to a dedicated set and to all
   * split sets.  The target attribute will not exist in any of the entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeFlatDITNonexistentAttribute()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", flatDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--attributeName", "displayName",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count = countEntries(outputDir, "output.ldif.set1");
    final int set2Count = countEntries(outputDir, "output.ldif.set2");
    final int set3Count = countEntries(outputDir, "output.ldif.set3");
    final int set4Count = countEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with an LDIF file that contains entries outside the split, the
   * split base entry, entries immediately below the split base entry, and
   * additional subordinate entries.  The entries outside the split will be only
   * to a dedicated set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeNonFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", branchedDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numThreads", "10",
         "--attributeName", "givenName",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the split base entry, and then the 26 entries below the split
    // base will be split individually, and the 26 subordinate entries should
    // always go to the same set as their parents, for a total of 56 entries.
    final Map<DN,Entry> set1Map = readEntries(outputDir, "output.ldif.set1");
    final Map<DN,Entry> set2Map = readEntries(outputDir, "output.ldif.set2");
    final Map<DN,Entry> set3Map = readEntries(outputDir, "output.ldif.set3");
    final Map<DN,Entry> set4Map = readEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Map.size() > 1);
    assertTrue(set2Map.size() > 1);
    assertTrue(set3Map.size() > 1);
    assertTrue(set4Map.size() > 1);

    assertEquals(
         (set1Map.size() + set2Map.size() + set3Map.size() + set4Map.size()),
         56);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with an LDIF file that contains entries outside the split, the
   * split base entry, entries immediately below the split base entry, and
   * additional subordinate entries.  The entries outside the split will be only
   * to a dedicated set.  A flat DIT will be assumed, so there should be errors
   * for all entries more than one level below the split base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeNonFlatDITAssumeFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", branchedDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--attributeName", "givenName",
         "--numSets", "4",
         "--assumeFlatDIT");
    assertEquals(rc, ResultCode.LOCAL_ERROR);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 6);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);

    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the split base entry, and then the 26 entries below the split
    // base will be split individually.  Because we assume a flat DIT, the
    // subordinate entries will be excluded from the split and will instead
    // be written to the error file.
    final Map<DN,Entry> set1Map = readEntries(outputDir, "output.ldif.set1");
    final Map<DN,Entry> set2Map = readEntries(outputDir, "output.ldif.set2");
    final Map<DN,Entry> set3Map = readEntries(outputDir, "output.ldif.set3");
    final Map<DN,Entry> set4Map = readEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Map.size() > 1);
    assertTrue(set2Map.size() > 1);
    assertTrue(set3Map.size() > 1);
    assertTrue(set4Map.size() > 1);

    assertEquals(
         (set1Map.size() + set2Map.size() + set3Map.size() + set4Map.size()),
         30);

    final Map<DN,Entry> errorMap =
         readEntries(outputDir, "output.ldif.errors", false, false, false);
    assertEquals(errorMap.size(), 26);
  }



  /**
   * Tests the behavior of the tool when using the split-using-hash-on-attribute
   * subcommand with an LDIF file that contains malformed entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashOnAttributeMalformedEntries()
         throws Exception
  {
    final File outputDir = createTempDir();

    final File sourceFile = new File(outputDir, "source.ldif");
    final PrintWriter w = new PrintWriter(sourceFile);
    w.println("dn: malformed DN");
    w.println("objectClass: top");
    w.println("objectClass: domain");
    w.println("dc: malformed DN");
    w.println("");
    w.println("dn: ou=malformed attribute,dc=malformed DN");
    w.println("objectClass: top");
    w.println("objectClass: organizationalUnit");
    w.println("malformed");
    w.println("");
    w.close();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-attribute",
         "--sourceLDIF", sourceFile.getAbsolutePath(),
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--attributeName", "givenName",
         "--numSets", "4");
    assertEquals(rc, ResultCode.LOCAL_ERROR);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 2); // Source and errors.

    assertTrue(new File(outputDir, "source.ldif.errors").exists());
    assertTrue(new File(outputDir, "source.ldif.errors").length() > 0L);
  }



  /**
   * Tests the behavior of the tool when using the split-using-fewest-entries
   * subcommand with an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestEntriesEmptyFile()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", emptyFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaFile.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 0);
  }



  /**
   * Tests the behavior of the tool when using the split-using-fewest-entries
   * subcommand with a file containing only entries outside the split when not
   * using any options that would cause those entries to be written.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestEntriesOnlyEntriesOutsideSplitNoneWritten()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 0);
  }



  /**
   * Tests the behavior of the tool when using the split-using-fewest-entries
   * subcommand with a file containing only entries outside the split when
   * those entries should only be written into a dedicated set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestEntriesOnlyEntriesOutsideSplitIntoDedicatedSet()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 1);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);
  }



  /**
   * Tests the behavior of the tool when using the split-using-fewest-entries
   * subcommand with a file containing only entries outside the split when
   * those entries should only be written into all sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestEntriesOnlyEntriesOutsideSplitIntoAllSets()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 4);

    assertEquals(countEntries(outputDir, "output.ldif.set1"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 2);
  }



  /**
   * Tests the behavior of the tool when using the split-using-fewest-entries
   * subcommand with a file containing only the split base entry itself, which
   * should be written into all sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestEntriesOnlySplitBaseEntry()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 4);

    assertEquals(countEntries(outputDir, "output.ldif.set1"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 1);
  }



  /**
   * Tests the behavior of the tool when using the split-using-fewest-entries
   * subcommand with a pair of files, the first containing only entries outside
   * the split and the second containing only the split base entry, when entries
   * outside the split should be written to a dedicated file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestEntriesOnlyOutsideAndSplitBaseEntrySeparateSets()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set1"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 1);
  }



  /**
   * Tests the behavior of the tool when using the split-using-fewest-entries
   * subcommand with a pair of files, the first containing only entries outside
   * the split and the second containing only the split base entry, when entries
   * outside the split should be written to all sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestEntriesOnlyOutsideAndSplitBaseEntryAllSets()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 4);

    assertEquals(countEntries(outputDir, "output.ldif.set1"), 3);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 3);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 3);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 3);
  }



  /**
   * Tests the behavior of the tool when using the split-using-fewest-entries
   * subcommand with an LDIF file that contains entries outside the split, the
   * split base entry, and entries immediately below the split base entry.  The
   * entries outside the split will be added both to a dedicated set and to all
   * split sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestEntriesFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", flatDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count = countEntries(outputDir, "output.ldif.set1");
    final int set2Count = countEntries(outputDir, "output.ldif.set2");
    final int set3Count = countEntries(outputDir, "output.ldif.set3");
    final int set4Count = countEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when using the split-using-fewest-entries
   * subcommand with an LDIF file that contains entries outside the split, the
   * split base entry, and entries immediately below the split base entry.  The
   * entries outside the split will be added both to a dedicated set and to all
   * split sets.  The --assumeFlatDIT option should be used, and should produce
   * behavior that is identical to the behavior without that option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestEntriesFlatDITAssumeFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", flatDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--numSets", "4",
         "--assumeFlatDIT");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count = countEntries(outputDir, "output.ldif.set1");
    final int set2Count = countEntries(outputDir, "output.ldif.set2");
    final int set3Count = countEntries(outputDir, "output.ldif.set3");
    final int set4Count = countEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when using the split-using-fewest-entries
   * subcommand with an LDIF file that contains entries outside the split, the
   * split base entry, entries immediately below the split base entry, and
   * additional subordinate entries.  The entries outside the split will be only
   * to a dedicated set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestEntriesNonFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", branchedDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numThreads", "10",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the split base entry, and then the 26 entries below the split
    // base will be split individually, and the 26 subordinate entries should
    // always go to the same set as their parents, for a total of 56 entries.
    final Map<DN,Entry> set1Map = readEntries(outputDir, "output.ldif.set1");
    final Map<DN,Entry> set2Map = readEntries(outputDir, "output.ldif.set2");
    final Map<DN,Entry> set3Map = readEntries(outputDir, "output.ldif.set3");
    final Map<DN,Entry> set4Map = readEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Map.size() > 1);
    assertTrue(set2Map.size() > 1);
    assertTrue(set3Map.size() > 1);
    assertTrue(set4Map.size() > 1);

    assertEquals(
         (set1Map.size() + set2Map.size() + set3Map.size() + set4Map.size()),
         56);
  }



  /**
   * Tests the behavior of the tool when using the split-using-fewest-entries
   * subcommand with an LDIF file that contains entries outside the split, the
   * split base entry, entries immediately below the split base entry, and
   * additional subordinate entries.  The entries outside the split will be only
   * to a dedicated set.  A flat DIT will be assumed, so there should be errors
   * for all entries more than one level below the split base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestEntriesNonFlatDITAssumeFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", branchedDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numSets", "4",
         "--assumeFlatDIT");
    assertEquals(rc, ResultCode.LOCAL_ERROR);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 6);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);

    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the split base entry, and then the 26 entries below the split
    // base will be split individually.  Because we assume a flat DIT, the
    // subordinate entries will be excluded from the split and will instead
    // be written to the error file.
    final Map<DN,Entry> set1Map = readEntries(outputDir, "output.ldif.set1");
    final Map<DN,Entry> set2Map = readEntries(outputDir, "output.ldif.set2");
    final Map<DN,Entry> set3Map = readEntries(outputDir, "output.ldif.set3");
    final Map<DN,Entry> set4Map = readEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Map.size() > 1);
    assertTrue(set2Map.size() > 1);
    assertTrue(set3Map.size() > 1);
    assertTrue(set4Map.size() > 1);

    assertEquals(
         (set1Map.size() + set2Map.size() + set3Map.size() + set4Map.size()),
         30);

    final Map<DN,Entry> errorMap =
         readEntries(outputDir, "output.ldif.errors", false, false, false);
    assertEquals(errorMap.size(), 26);
  }



  /**
   * Tests the behavior of the tool when using the split-using-fewest-entries
   * subcommand with an LDIF file that contains malformed entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestEntriesMalformedEntries()
         throws Exception
  {
    final File outputDir = createTempDir();

    final File sourceFile = new File(outputDir, "source.ldif");
    final PrintWriter w = new PrintWriter(sourceFile);
    w.println("dn: malformed DN");
    w.println("objectClass: top");
    w.println("objectClass: domain");
    w.println("dc: malformed DN");
    w.println("");
    w.println("dn: ou=malformed attribute,dc=malformed DN");
    w.println("objectClass: top");
    w.println("objectClass: organizationalUnit");
    w.println("malformed");
    w.println("");
    w.close();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", sourceFile.getAbsolutePath(),
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numSets", "4");
    assertEquals(rc, ResultCode.LOCAL_ERROR);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 2); // Source and errors.

    assertTrue(new File(outputDir, "source.ldif.errors").exists());
    assertTrue(new File(outputDir, "source.ldif.errors").length() > 0L);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterEmptyFile()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", emptyFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaFile.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=m)",
         "--filter", "(givenName<=t)",
         "--filter", "(givenName=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 0);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * when only a single filter was provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterOnlyOneFilter()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", emptyFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaFile.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--filter", "(givenName<=g)");
    assertEquals(rc, ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * when duplicate filters were provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterDuplicateFilters()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", emptyFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaFile.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=g)");
    assertEquals(rc, ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with a file containing only entries outside the split when not using any
   * options that would cause those entries to be written.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterOnlyEntriesOutsideSplitNoneWritten()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=m)",
         "--filter", "(givenName<=t)",
         "--filter", "(givenName=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 0);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with a file containing only entries outside the split when those entries
   * should only be written into a dedicated set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterOnlyEntriesOutsideSplitIntoDedicatedSet()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=m)",
         "--filter", "(givenName<=t)",
         "--filter", "(givenName=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 1);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with a file containing only entries outside the split when those entries
   * should only be written into all sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterOnlyEntriesOutsideSplitIntoAllSets()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", schemaDir.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=m)",
         "--filter", "(givenName<=t)",
         "--filter", "(givenName=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 4);

    assertEquals(countEntries(outputDir, "output.ldif.set1"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 2);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with a file containing only the split base entry itself, which should be
   * written into all sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterOnlySplitBaseEntry()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=m)",
         "--filter", "(givenName<=t)",
         "--filter", "(givenName=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 4);

    assertEquals(countEntries(outputDir, "output.ldif.set1"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 1);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with a pair of files, the first containing only entries outside the split
   * and the second containing only the split base entry, when entries outside
   * the split should be written to a dedicated file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterOnlyOutsideAndSplitBaseEntrySeparateSets()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=m)",
         "--filter", "(givenName<=t)",
         "--filter", "(givenName=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);
    assertEquals(countEntries(outputDir, "output.ldif.set1"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 1);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 1);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with a pair of files, the first containing only entries outside the split
   * and the second containing only the split base entry, when entries outside
   * the split should be written to all sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterOnlyOutsideAndSplitBaseEntryAllSets()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=m)",
         "--filter", "(givenName<=t)",
         "--filter", "(givenName=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 4);

    assertEquals(countEntries(outputDir, "output.ldif.set1"), 3);
    assertEquals(countEntries(outputDir, "output.ldif.set2"), 3);
    assertEquals(countEntries(outputDir, "output.ldif.set3"), 3);
    assertEquals(countEntries(outputDir, "output.ldif.set4"), 3);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with an LDIF file that contains entries outside the split, the split base
   * entry, and entries immediately below the split base entry.  The entries
   * outside the split will be added both to a dedicated set and to all split
   * sets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", flatDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=m)",
         "--filter", "(givenName<=t)",
         "--filter", "(givenName=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count = countEntries(outputDir, "output.ldif.set1");
    final int set2Count = countEntries(outputDir, "output.ldif.set2");
    final int set3Count = countEntries(outputDir, "output.ldif.set3");
    final int set4Count = countEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with an LDIF file that contains entries outside the split, the split base
   * entry, and entries immediately below the split base entry.  The entries
   * outside the split will be added both to a dedicated set and to all split
   * sets.  None of the filters provided will match any entries, so it will fall
   * back to splitting based on RDN hashes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterFlatDITNonMatchingFilters()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", flatDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--filter", "(displayName<=g)",
         "--filter", "(displayName<=m)",
         "--filter", "(displayName<=t)",
         "--filter", "(displayName=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count = countEntries(outputDir, "output.ldif.set1");
    final int set2Count = countEntries(outputDir, "output.ldif.set2");
    final int set3Count = countEntries(outputDir, "output.ldif.set3");
    final int set4Count = countEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with an LDIF file that contains entries outside the split, the split base
   * entry, and entries immediately below the split base entry.  The entries
   * outside the split will be added both to a dedicated set and to all split
   * sets.  The LDAP SDK will not support the filters used, and will therefore
   * fall back to splitting based on an RDN hash.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterFlatDITUnsupportedFilters()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", flatDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--filter", "(givenName~=unsupported 1)",
         "--filter", "(givenName~=unsupported 2)",
         "--filter", "(givenName~=unsupported 3)",
         "--filter", "(givenName~=unsupported 4)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count = countEntries(outputDir, "output.ldif.set1");
    final int set2Count = countEntries(outputDir, "output.ldif.set2");
    final int set3Count = countEntries(outputDir, "output.ldif.set3");
    final int set4Count = countEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with an LDIF file that contains entries outside the split, the split base
   * entry, and entries immediately below the split base entry.  The entries
   * outside the split will be added both to a dedicated set and to all split
   * sets.  The --assumeFlatDIT option should be used, and should produce
   * behavior that is identical to the behavior without that option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterFlatDITAssumeFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", flatDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=m)",
         "--filter", "(givenName<=t)",
         "--filter", "(givenName=*)",
         "--assumeFlatDIT");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count = countEntries(outputDir, "output.ldif.set1");
    final int set2Count = countEntries(outputDir, "output.ldif.set2");
    final int set3Count = countEntries(outputDir, "output.ldif.set3");
    final int set4Count = countEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with an LDIF file that contains entries outside the split, the split base
   * entry, entries immediately below the split base entry, and additional
   * subordinate entries.  The entries outside the split will be only to a
   * dedicated set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterNonFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", branchedDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numThreads", "10",
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=m)",
         "--filter", "(givenName<=t)",
         "--filter", "(givenName=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the split base entry, and then the 26 entries below the split
    // base will be split individually, and the 26 subordinate entries should
    // always go to the same set as their parents, for a total of 56 entries.
    final Map<DN,Entry> set1Map = readEntries(outputDir, "output.ldif.set1");
    final Map<DN,Entry> set2Map = readEntries(outputDir, "output.ldif.set2");
    final Map<DN,Entry> set3Map = readEntries(outputDir, "output.ldif.set3");
    final Map<DN,Entry> set4Map = readEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Map.size() > 1);
    assertTrue(set2Map.size() > 1);
    assertTrue(set3Map.size() > 1);
    assertTrue(set4Map.size() > 1);

    assertEquals(
         (set1Map.size() + set2Map.size() + set3Map.size() + set4Map.size()),
         56);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with an LDIF file that contains entries outside the split, the split base
   * entry, entries immediately below the split base entry, and additional
   * subordinate entries.  The entries outside the split will be only to a
   * dedicated set.  A flat DIT will be assumed, so there should be errors for
   * all entries more than one level below the split base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterNonFlatDITAssumeFlatDIT()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", branchedDITFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=m)",
         "--filter", "(givenName<=t)",
         "--filter", "(givenName=*)",
         "--assumeFlatDIT");
    assertEquals(rc, ResultCode.LOCAL_ERROR);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 6);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);

    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the split base entry, and then the 26 entries below the split
    // base will be split individually.  Because we assume a flat DIT, the
    // subordinate entries will be excluded from the split and will instead
    // be written to the error file.
    final Map<DN,Entry> set1Map = readEntries(outputDir, "output.ldif.set1");
    final Map<DN,Entry> set2Map = readEntries(outputDir, "output.ldif.set2");
    final Map<DN,Entry> set3Map = readEntries(outputDir, "output.ldif.set3");
    final Map<DN,Entry> set4Map = readEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Map.size() > 1);
    assertTrue(set2Map.size() > 1);
    assertTrue(set3Map.size() > 1);
    assertTrue(set4Map.size() > 1);

    assertEquals(
         (set1Map.size() + set2Map.size() + set3Map.size() + set4Map.size()),
         30);

    final Map<DN,Entry> errorMap =
         readEntries(outputDir, "output.ldif.errors", false, false, false);
    assertEquals(errorMap.size(), 26);
  }



  /**
   * Tests the behavior of the tool when using the split-using-filter subcommand
   * with an LDIF file that contains malformed entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterMalformedEntries()
         throws Exception
  {
    final File outputDir = createTempDir();

    final File sourceFile = new File(outputDir, "source.ldif");
    final PrintWriter w = new PrintWriter(sourceFile);
    w.println("dn: malformed DN");
    w.println("objectClass: top");
    w.println("objectClass: domain");
    w.println("dc: malformed DN");
    w.println("");
    w.println("dn: ou=malformed attribute,dc=malformed DN");
    w.println("objectClass: top");
    w.println("objectClass: organizationalUnit");
    w.println("malformed");
    w.println("");
    w.close();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-filter",
         "--sourceLDIF", sourceFile.getAbsolutePath(),
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--filter", "(givenName<=g)",
         "--filter", "(givenName<=m)",
         "--filter", "(givenName<=t)",
         "--filter", "(givenName=*)");
    assertEquals(rc, ResultCode.LOCAL_ERROR);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 2); // Source and errors.

    assertTrue(new File(outputDir, "source.ldif.errors").exists());
    assertTrue(new File(outputDir, "source.ldif.errors").length() > 0L);
  }



  /**
   * Tests the behavior of the tool when run with multiple source files but no
   * target base path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleSourceFilesWithoutTargetBasePath()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numSets", "4");
    assertEquals(rc, ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the behavior when a schema path is provided that refers to an empty
   * directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoSchemaFiles()
         throws Exception
  {
    final File emptySchemaDir = createTempDir();
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", onlyEntriesOutsideSplitFile.getAbsolutePath(),
         "--sourceLDIF", onlySplitBaseEntryFile.getAbsolutePath(),
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--schemaPath", emptySchemaDir.getAbsolutePath(),
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--numSets", "4");
    assertEquals(rc, ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the behavior of the tool when the input is compressed but the output
   * is not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompressedInput()
         throws Exception
  {
    final File sourceDir = createTempDir();
    final File sourceFile = new File(sourceDir, "source.ldif");

    final LDIFWriter sourceWriter =
         new LDIFWriter(new GZIPOutputStream(new FileOutputStream(sourceFile)));
    for (final Entry e :
         readEntries(flatDITFile.getParentFile(),
              flatDITFile.getName()).values())
    {
      sourceWriter.writeEntry(e);
    }
    sourceWriter.close();


    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", sourceFile.getAbsolutePath(),
         "--sourceCompressed",
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(countEntries(outputDir, "output.ldif.outside-split"), 2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count = countEntries(outputDir, "output.ldif.set1");
    final int set2Count = countEntries(outputDir, "output.ldif.set2");
    final int set3Count = countEntries(outputDir, "output.ldif.set3");
    final int set4Count = countEntries(outputDir, "output.ldif.set4");

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when the input is not compressed but the
   * output will be.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompressOutput()
         throws Exception
  {
    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    try
    {
      PasswordReader.setTestReaderLines("passphrase", "passphrase");

      final ResultCode rc = SplitLDIF.main(out, out,
           "split-using-hash-on-rdn",
           "--sourceLDIF", flatDITFile.getAbsolutePath(),
           "--targetLDIFBasePath",
           outputDir.getAbsolutePath() + File.separator + "output.ldif",
           "--compressTarget",
           "--encryptTarget",
           "--splitBaseDN", "ou=People,dc=example,dc=com",
           "--addEntriesOutsideSplitBaseDNToDedicatedSet",
           "--addEntriesOutsideSplitBaseDNToAllSets",
           "--numSets", "4");
      assertEquals(rc, ResultCode.SUCCESS);
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(
         readEntries(outputDir, "output.ldif.outside-split", true, true,
              true).size(),
         2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count =
         readEntries(outputDir, "output.ldif.set1", true, true, true).size();
    final int set2Count =
         readEntries(outputDir, "output.ldif.set2", true, true, true).size();
    final int set3Count =
         readEntries(outputDir, "output.ldif.set3", true, true, true).size();
    final int set4Count =
         readEntries(outputDir, "output.ldif.set4", true, true, true).size();

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when both the input and output are
   * compressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompressedInputAndOutput()
         throws Exception
  {
    final File sourceDir = createTempDir();
    final File sourceFile = new File(sourceDir, "source.ldif");

    final LDIFWriter sourceWriter =
         new LDIFWriter(new GZIPOutputStream(new FileOutputStream(sourceFile)));
    for (final Entry e :
         readEntries(flatDITFile.getParentFile(),
              flatDITFile.getName()).values())
    {
      sourceWriter.writeEntry(e);
    }
    sourceWriter.close();


    final File outputDir = createTempDir();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-hash-on-rdn",
         "--sourceLDIF", sourceFile.getAbsolutePath(),
         "--sourceCompressed",
         "--targetLDIFBasePath",
              outputDir.getAbsolutePath() + File.separator + "output.ldif",
         "--compressTarget",
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--addEntriesOutsideSplitBaseDNToDedicatedSet",
         "--addEntriesOutsideSplitBaseDNToAllSets",
         "--numSets", "4");
    assertEquals(rc, ResultCode.SUCCESS);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 5);

    assertEquals(
         readEntries(outputDir, "output.ldif.outside-split", true, true,
              false).size(),
         2);


    // Since it's not obvious which entries will go to which sets, we can
    // just make sure that at least some entries have gone to each set and that
    // we have the expected total number of entries across all sets.  All sets
    // will have the three entries at and outside the split base, and then the
    // 26 entries below the split base will be split individually, for a total
    // of 38 entries.
    final int set1Count =
         readEntries(outputDir, "output.ldif.set1", true, true, false).size();
    final int set2Count =
         readEntries(outputDir, "output.ldif.set2", true, true, false).size();
    final int set3Count =
         readEntries(outputDir, "output.ldif.set3", true, true, false).size();
    final int set4Count =
         readEntries(outputDir, "output.ldif.set4", true, true, false).size();

    assertTrue(set1Count > 3);
    assertTrue(set2Count > 3);
    assertTrue(set3Count > 3);
    assertTrue(set4Count > 3);

    assertEquals((set1Count + set2Count + set3Count + set4Count), 38);
  }



  /**
   * Tests the behavior of the tool when attempting to process an entry that is
   * more than one level below the split base DN when its parent doesn't exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubordinateEntryMissingParent()
         throws Exception
  {
    final File outputDir = createTempDir();

    final File sourceFile = new File(outputDir, "source.ldif");
    final PrintWriter w = new PrintWriter(sourceFile);
    w.println("dn: ou=test,ou=Missing,ou=People,dc=example,dc=com");
    w.println("objectClass: top");
    w.println("objectClass: organizationalUnit");
    w.println("ou: test");
    w.println("");
    w.close();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final ResultCode rc = SplitLDIF.main(out, out,
         "split-using-fewest-entries",
         "--sourceLDIF", sourceFile.getAbsolutePath(),
         "--splitBaseDN", "ou=People,dc=example,dc=com",
         "--numSets", "4");
    assertEquals(rc, ResultCode.LOCAL_ERROR);

    assertNotNull(outputDir.listFiles());
    assertEquals(outputDir.listFiles().length, 2); // Source and errors.

    assertTrue(new File(outputDir, "source.ldif.errors").exists());
    assertTrue(new File(outputDir, "source.ldif.errors").length() > 0L);
  }



  /**
   * Counts the number of entries in the specified LDIF file.  For each entry
   * below the split base DN, the method will also ensure that its parent is
   * also included in the LDIF file before that entry.
   *
   * @param  dir       The directory in which the file exists.
   * @param  filename  The name of the LDIF file.
   *
   * @return  A map of the entries read from the specified file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static int countEntries(final File dir, final String filename)
          throws Exception
  {
    return readEntries(dir, filename).size();
  }




  /**
   * Reads all the entries in the specified LDIF file into a map.  For each
   * entry below the split base DN, the method will also ensure that its parent
   * is also included in the LDIF file before that entry.
   *
   * @param  dir       The directory in which the file exists.
   * @param  filename  The name of the LDIF file.
   *
   * @return  A map of the entries read from the specified file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static TreeMap<DN,Entry> readEntries(final File dir,
                                               final String filename)
          throws Exception
  {
    return readEntries(dir, filename, true, false, false);
  }




  /**
   * Reads all the entries in the specified LDIF file into a map.  For each
   * entry below the split base DN, the method will also optionally ensure that
   * its parent is also included in the LDIF file before that entry.
   *
   * @param  dir           The directory in which the file exists.
   * @param  filename      The name of the LDIF file.
   * @param  checkParent   Indicates whether to ensure that the parent entry
   *                       exists for all entries below the split base DN.
   * @param  isCompressed  Indicates whether the input file is compressed.
   * @param  isEncrypted   Indicates whether the input file is encrypted.
   *
   * @return  A map of the entries read from the specified file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static TreeMap<DN,Entry> readEntries(final File dir,
                                               final String filename,
                                               final boolean checkParent,
                                               final boolean isCompressed,
                                               final boolean isEncrypted)
          throws Exception
  {
    final DN splitBaseDN = new DN("ou=People,dc=example,dc=com");

    final File f = new File(dir, filename);

    InputStream inputStream = new FileInputStream(f);
    if (isEncrypted)
    {
      inputStream =
           new PassphraseEncryptedInputStream("passphrase", inputStream);
    }

    if (isCompressed)
    {
      inputStream = new GZIPInputStream(inputStream);
    }

    final LDIFReader r = new LDIFReader(inputStream);

    final TreeMap<DN,Entry> m = new TreeMap<DN,Entry>();
    while (true)
    {
      final Entry e = r.readEntry();
      if (e == null)
      {
        break;
      }

      final DN dn = e.getParsedDN();
      if (checkParent && dn.isDescendantOf(splitBaseDN, false))
      {
        assertTrue(m.containsKey(dn.getParent()),
             "Found entry " + dn + " in " + f.getAbsolutePath() +
                  " without parent " + dn.getParent());
      }

      m.put(dn, e);
    }

    r.close();
    return m;
  }
}
