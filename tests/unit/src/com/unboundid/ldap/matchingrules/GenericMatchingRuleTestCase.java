/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.matchingrules;



import java.util.ArrayList;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.unboundidds.jsonfilter.
            JSONObjectExactMatchingRule;



/**
 * Tests the methods used to select an appropriate matching rule for a given
 * attribute.
 */
public class GenericMatchingRuleTestCase
       extends MatchingRuleTestCase
{
  // The schema read from the test directory, if available.
  private Schema schema;



  /**
   * Retrieves the schema from the directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void getSchema()
         throws Exception
  {
    final LDAPConnection conn;
    if (isDirectoryInstanceAvailable())
    {
      conn = getAdminConnection();
    }
    else
    {
      conn = getTestDS().getConnection();
    }

    schema = conn.getSchema();
    conn.close();
  }



  /**
   * Tests to ensure that the {@code selectEqualityMatchingRule} method always
   * returns a value.
   *
   * @param  attrName  The name of an attribute for which to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeNames")
  public void testSelectEqualityMatchingRule(String attrName)
         throws Exception
  {
    assertNotNull(MatchingRule.selectEqualityMatchingRule(attrName, null));
    assertNotNull(MatchingRule.selectEqualityMatchingRule(
         attrName + "-undefined", null));
    assertNotNull(MatchingRule.selectEqualityMatchingRule(attrName, schema));
    assertNotNull(MatchingRule.selectEqualityMatchingRule(attrName, "2.5.13.2",
         schema));
    assertNotNull(MatchingRule.selectEqualityMatchingRule(attrName, "",
         schema));
    assertNotNull(MatchingRule.selectEqualityMatchingRule(attrName,
         "2.5.13.1245", schema));
    assertNotNull(MatchingRule.selectEqualityMatchingRule(null, "2.5.13.2",
         schema));
    assertNotNull(MatchingRule.selectEqualityMatchingRule(null, "2.5.13.2",
         null));
    assertNotNull(MatchingRule.selectEqualityMatchingRule(null, null, null));
  }



  /**
   * Tests to ensure that the {@code selectOrderingMatchingRule} method always
   * returns a value.
   *
   * @param  attrName  The name of an attribute for which to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeNames")
  public void testSelectOrderingMatchingRule(String attrName)
         throws Exception
  {
    assertNotNull(MatchingRule.selectOrderingMatchingRule(attrName, null));
    assertNotNull(MatchingRule.selectOrderingMatchingRule(
         attrName + "-undefined", null));
    assertNotNull(MatchingRule.selectOrderingMatchingRule(attrName, schema));
    assertNotNull(MatchingRule.selectOrderingMatchingRule(attrName, "2.5.13.3",
         schema));
    assertNotNull(MatchingRule.selectOrderingMatchingRule(attrName, "",
         schema));
    assertNotNull(MatchingRule.selectOrderingMatchingRule(attrName,
         "2.5.13.12345", schema));
    assertNotNull(MatchingRule.selectOrderingMatchingRule(null, "2.5.13.3",
         schema));
    assertNotNull(MatchingRule.selectOrderingMatchingRule(null, "2.5.13.3",
         null));
    assertNotNull(MatchingRule.selectOrderingMatchingRule(null, null, null));
  }



  /**
   * Tests to ensure that the {@code selectSubstringMatchingRule} method always
   * returns a value.
   *
   * @param  attrName  The name of an attribute for which to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeNames")
  public void testSelectSubstringMatchingRule(String attrName)
         throws Exception
  {
    assertNotNull(MatchingRule.selectSubstringMatchingRule(attrName, null));
    assertNotNull(MatchingRule.selectSubstringMatchingRule(
         attrName + "-undefined", null));
    assertNotNull(MatchingRule.selectSubstringMatchingRule(attrName, schema));
    assertNotNull(MatchingRule.selectSubstringMatchingRule(attrName, "2.5.13.4",
         schema));
    assertNotNull(MatchingRule.selectSubstringMatchingRule(attrName, "",
         schema));
    assertNotNull(MatchingRule.selectSubstringMatchingRule(attrName,
         "2.5.13.12345", schema));
    assertNotNull(MatchingRule.selectSubstringMatchingRule(null, "2.5.13.4",
         schema));
    assertNotNull(MatchingRule.selectSubstringMatchingRule(null, "2.5.13.4",
         null));
    assertNotNull(MatchingRule.selectSubstringMatchingRule(null, null, null));
  }



  /**
   * Retrieves a set of attribute names to use for testing.
   *
   * @return  A set of attribute names to use for testing.
   */
  @DataProvider(name="attributeNames")
  public Object[][] getAttributeNames()
  {
    ArrayList<String> attrList = new ArrayList<String>();
    attrList.add("probablyNotInTheServerSchema");

    if (schema != null)
    {
      for (AttributeTypeDefinition at : schema.getAttributeTypes())
      {
        attrList.add(at.getOID());
        for (String s : at.getNames())
        {
          attrList.add(s);
        }
      }
    }

    Object[][] attrArray = new Object[attrList.size()][1];
    for (int i=0; i < attrArray.length; i++)
    {
      attrArray[i][0] = attrList.get(i);
    }

    return attrArray;
  }



  /**
   * Tests to ensure that the methods for selecting matching rules based on
   * names or OIDs work as expected.
   *
   * @param  mr  The matching rule to be tested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="matchingRules")
  public void testSelectMatchingRules(MatchingRule mr)
         throws Exception
  {
    String eqOID = mr.getEqualityMatchingRuleOID();
    if (eqOID != null)
    {
      assertEquals(MatchingRule.selectEqualityMatchingRule(eqOID), mr);
      assertEquals(MatchingRule.selectEqualityMatchingRule(
           mr.getEqualityMatchingRuleName()), mr);
    }

    String ordOID = mr.getOrderingMatchingRuleOID();
    if (ordOID != null)
    {
      assertEquals(MatchingRule.selectOrderingMatchingRule(ordOID), mr);
      assertEquals(MatchingRule.selectOrderingMatchingRule(
           mr.getOrderingMatchingRuleName()), mr);
    }

    String subOID = mr.getSubstringMatchingRuleOID();
    if (subOID != null)
    {
      assertEquals(MatchingRule.selectSubstringMatchingRule(subOID), mr);
      assertEquals(MatchingRule.selectSubstringMatchingRule(
           mr.getSubstringMatchingRuleName()), mr);
    }
  }



  /**
   * Retrieves a set of matching rules that can be used for testing.
   *
   * @return  A set of matching rules that can be used for testing.
   */
  @DataProvider(name="matchingRules")
  public Object[][] getMatchingRules()
  {
    return new Object[][]
    {
      new Object[] { BooleanMatchingRule.getInstance() },
      new Object[] { CaseExactStringMatchingRule.getInstance() },
      new Object[] { CaseIgnoreListMatchingRule.getInstance() },
      new Object[] { CaseIgnoreStringMatchingRule.getInstance() },
      new Object[] { DistinguishedNameMatchingRule.getInstance() },
      new Object[] { GeneralizedTimeMatchingRule.getInstance() },
      new Object[] { IntegerMatchingRule.getInstance() },
      new Object[] { NumericStringMatchingRule.getInstance() },
      new Object[] { OctetStringMatchingRule.getInstance() },
      new Object[] { TelephoneNumberMatchingRule.getInstance() },
      new Object[] { JSONObjectExactMatchingRule.getInstance() }
    };
  }



  /**
   * Tests to ensure that the methods for selecting matching rules based on
   * syntax work as expected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSelectMatchingRuleForSyntax()
         throws Exception
  {
    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.7"),
         BooleanMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.41"),
         CaseIgnoreListMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.12"),
         DistinguishedNameMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.34"),
         DistinguishedNameMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.24"),
         GeneralizedTimeMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.53"),
         GeneralizedTimeMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.27"),
         IntegerMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.36"),
         NumericStringMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.4203.1.1.2"),
         OctetStringMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.5"),
         OctetStringMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.8"),
         OctetStringMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.9"),
         OctetStringMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.10"),
         OctetStringMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.40"),
         OctetStringMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.1466.115.121.1.50"),
         TelephoneNumberMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.2.3.4.5"),
         CaseIgnoreStringMatchingRule.getInstance());

    assertEquals(MatchingRule.selectMatchingRuleForSyntax(
         "1.3.6.1.4.1.30221.2.3.4"),
         JSONObjectExactMatchingRule.getInstance());
  }
}
