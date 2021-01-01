/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.examples;



import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the {@code IndentLDAPFilter}
 * tool.
 */
public final class IndentLDAPFilterTestCase
       extends LDAPSDKTestCase
{
  /**
   * A {@code null} {@code OutputStream} reference.
   */
  private static final OutputStream NULL_OUTPUT_STREAM = null;



  /**
   * Invokes the tool to obtain usage information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    assertEquals(
         IndentLDAPFilter.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--help"),
         ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior of the tool when invoked without simplification.
   *
   * @param  filterString    A string representation of a filter to be indented.
   * @param  numSpaces       The number of extra spaces to indent the output.
   * @param  expectedOutput  The expected output from the tool.
   * @param  canSimplify     Indicates whether the provided filter can be
   *                         simplified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testData")
  public void testToolWithoutSimplficiation(final String filterString,
                                            final int numSpaces,
                                            final List<String> expectedOutput,
                                            final boolean canSimplify)
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         IndentLDAPFilter.main(out, out,
              "--indent-spaces", String.valueOf(numSpaces),
              "--do-not-simplify",
              filterString),
         ResultCode.SUCCESS);

    final List<String> gotOutput = outputToStrings(out);
    assertEquals(gotOutput, expectedOutput,
         "Expected:" +
              StaticUtils.EOL +
              StaticUtils.EOL +
              listToMultiLineString(expectedOutput) +
              StaticUtils.EOL +
              StaticUtils.EOL +
              "But got:" +
              StaticUtils.EOL +
              StaticUtils.EOL +
              listToMultiLineString(gotOutput));
  }



  /**
   * Tests the behavior of the tool when invoked with simplification enabled.
   *
   * @param  filterString    A string representation of a filter to be indented.
   * @param  numSpaces       The number of extra spaces to indent the output.
   * @param  expectedOutput  The expected output from the tool.
   * @param  canSimplify     Indicates whether the provided filter can be
   *                         simplified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testData")
  public void testToolWithSimplficiation(final String filterString,
                                         final int numSpaces,
                                         final List<String> expectedOutput,
                                         final boolean canSimplify)
         throws Exception
  {
    final Filter originalFilter = Filter.create(filterString);
    final Filter simplifiedFilter =
         Filter.simplifyFilter(originalFilter, false);
    if (canSimplify)
    {
      assertFalse(originalFilter.equals(simplifiedFilter));
    }
    else
    {
      assertTrue(originalFilter.equals(simplifiedFilter));
    }


    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         IndentLDAPFilter.main(out, out,
              "--indent-spaces", String.valueOf(numSpaces),
              filterString),
         ResultCode.SUCCESS);


    final ArrayList<String> expectedOutputWithSimplification =
         new ArrayList<>(expectedOutput.size() * 3);
    expectedOutputWithSimplification.addAll(expectedOutput);

    expectedOutputWithSimplification.add("");
    if (canSimplify)
    {
      expectedOutputWithSimplification.add(
           "The provided filter can be simplified to:");
      expectedOutputWithSimplification.add("");
      expectedOutputWithSimplification.add("     " +
           simplifiedFilter.toString());
      expectedOutputWithSimplification.add("");
      expectedOutputWithSimplification.add(
           "An indented representation of the simplified filter:");
      expectedOutputWithSimplification.add("");

      final StringBuilder indentSpacesBuffer = new StringBuilder();
      for (int i=0; i < numSpaces; i++)
      {
        indentSpacesBuffer.append(' ');
      }
      final String indentSpaces = indentSpacesBuffer.toString();

      IndentLDAPFilter.indentLDAPFilter(simplifiedFilter, "",
           indentSpaces, expectedOutputWithSimplification);
    }
    else
    {
      expectedOutputWithSimplification.add(
           "The provided filter cannot be simplified.");
    }


    final List<String> gotOutput = outputToStrings(out);
    assertEquals(gotOutput, expectedOutputWithSimplification,
         "Expected:" +
              StaticUtils.EOL +
              StaticUtils.EOL +
              listToMultiLineString(expectedOutputWithSimplification) +
              StaticUtils.EOL +
              StaticUtils.EOL +
              "But got:" +
              StaticUtils.EOL +
              StaticUtils.EOL +
              listToMultiLineString(gotOutput));
  }



  /**
   * Tests the behavior of the tool when trying to run with an invalid filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolWithInvalidFilter()
         throws Exception
  {
    assertEquals(
         IndentLDAPFilter.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "this is not a valid filter"),
         ResultCode.FILTER_ERROR);
  }



  /**
   * Retrieves a set of test data that may be used for testing the indent
   * filter tool.  Each element of the array returned will itself be a
   * four-element array, containing a string representation of a filter to be
   * indented, an integer value that represents the number of extra spaces to
   * indent the filter, a list of the strings that represent the expected
   * indented output from that filter (when simplification is disabled), and an
   * indication as to whether the provided filter can be simplified.
   *
   * @return  A set of test data that may be used for testing the indent filter
   *          tool.
   */
  @DataProvider(name = "testData")
  public Object[][] getTestData()
  {
    return new Object[][]
    {
      new Object[]
      {
        "(objectClass=*)",
        0,
        Collections.singletonList("(objectClass=*)"),
        false
      },

      new Object[]
      {
        "(objectClass=*)",
        5,
        Collections.singletonList("(objectClass=*)"),
        false
      },

      new Object[]
      {
        "(&(givenName=John)(sn=Doe))",
        0,
        Arrays.asList(
             "(&",
             " &(givenName=John)",
             " &(sn=Doe)",
             " &)"),
        false
      },

      new Object[]
      {
        "(&(givenName=John)(sn=Doe))",
        2,
        Arrays.asList(
             "(&",
             " &  (givenName=John)",
             " &  (sn=Doe)",
             " &)"),
        false
      },

      new Object[]
      {
        "(&(givenName=John)(sn=Doe))",
        5,
        Arrays.asList(
             "(&",
             " &     (givenName=John)",
             " &     (sn=Doe)",
             " &)"),
        false
      },

      new Object[]
      {
        "(&(givenName=John)(&(sn=Doe)))",
        5,
        Arrays.asList(
             "(&",
             " &     (givenName=John)",
             " &     (&",
             " &      &     (sn=Doe)",
             " &      &)",
             " &)"),
        true
      },

      new Object[]
      {
        "(|(givenName=foo)(sn=foo)(cn=foo)(uid=foo)(mail=foo))",
        2,
        Arrays.asList(
             "(|",
             " |  (givenName=foo)",
             " |  (sn=foo)",
             " |  (cn=foo)",
             " |  (uid=foo)",
             " |  (mail=foo)",
             " |)"),
        false
      },

      new Object[]
      {
        "(|(givenName=foo)(|(sn=foo)(|(cn=foo)(|(uid=foo)(mail=foo)))))",
        2,
        Arrays.asList(
             "(|",
             " |  (givenName=foo)",
             " |  (|",
             " |   |  (sn=foo)",
             " |   |  (|",
             " |   |   |  (cn=foo)",
             " |   |   |  (|",
             " |   |   |   |  (uid=foo)",
             " |   |   |   |  (mail=foo)",
             " |   |   |   |)",
             " |   |   |)",
             " |   |)",
             " |)"),
        true
      },

      new Object[]
      {
        "(|(&(objectClass=groupOfNames)" +
             "(member=uid=jdoe,ou=People,dc=example,dc=com))" +
             "(&(objectClass=groupOfUniqueNames)" +
             "(uniqueMember=uid=jdoe,ou=People,dc=example,dc=com)))",
        2,
        Arrays.asList(
             "(|",
             " |  (&",
             " |   &  (objectClass=groupOfNames)",
             " |   &  (member=uid=jdoe,ou=People,dc=example,dc=com)",
             " |   &)",
             " |  (&",
             " |   &  (objectClass=groupOfUniqueNames)",
             " |   &  (uniqueMember=uid=jdoe,ou=People,dc=example,dc=com)",
             " |   &)",
             " |)"),
        false
      },

      new Object[]
      {
        "(&(|(objectClass=groupOfNames)" +
             "(objectClass=groupOfUniqueNames))" +
             "(|(member=uid=jdoe,ou=People,dc=example,dc=com)" +
             "(uniqueMember=uid=jdoe,ou=People,dc=example,dc=com)))",
        2,
        Arrays.asList(
             "(&",
             " &  (|",
             " &   |  (objectClass=groupOfNames)",
             " &   |  (objectClass=groupOfUniqueNames)",
             " &   |)",
             " &  (|",
             " &   |  (member=uid=jdoe,ou=People,dc=example,dc=com)",
             " &   |  (uniqueMember=uid=jdoe,ou=People,dc=example,dc=com)",
             " &   |)",
             " &)"),
        false
      },

      new Object[]
      {
        "(&(&)(objectClass=*)(givenName=John)(sn~=Doe)(cn=John*)" +
             "(&(createTimestamp>=20190101000000.000Z)" +
             "(createTimestamp<=20190102000000.000Z))(dc:dn:=example)(!(|" +
             "(|)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))))",
        2,
        Arrays.asList(
             "(&",
             " &  (&)",
             " &  (objectClass=*)",
             " &  (givenName=John)",
             " &  (sn~=Doe)",
             " &  (cn=John*)",
             " &  (&",
             " &   &  (createTimestamp>=20190101000000.000Z)",
             " &   &  (createTimestamp<=20190102000000.000Z)",
             " &   &)",
             " &  (dc:dn:=example)",
             " &  (!",
             " &   !  (|",
             " &   !   |  (|)",
             " &   !   |  (objectClass=groupOfNames)",
             " &   !   |  (objectClass=groupOfUniqueNames)",
             " &   !   |)",
             " &   !)",
             " &)"),
        true
      },
    };
  }



  /**
   * Converts the provided output to a list of strings.
   *
   * @param  out  The {@code ByteArrayOutputStream} whose data should be
   *              consumed and converted to a list of strings.
   *
   * @return  The list of strings obtained from the provided output.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static List<String> outputToStrings(final ByteArrayOutputStream out)
          throws Exception
  {
    try (final ByteArrayInputStream byteArrayInputStream =
              new ByteArrayInputStream(out.toByteArray());
         final InputStreamReader inputStreamReader =
              new InputStreamReader(byteArrayInputStream);
         final BufferedReader bufferedReader =
              new BufferedReader(inputStreamReader))
    {
      final ArrayList<String> lines = new ArrayList<>(10);
      while (true)
      {
        final String line = bufferedReader.readLine();
        if (line == null)
        {
          return Collections.unmodifiableList(lines);
        }
        else
        {
          lines.add(line);
        }
      }
    }
  }



  /**
   * Retrieves a multi-line string representation of all the strings in the
   * provided list.
   *
   * @param  l  The list to be converted to a multi-line string.
   *
   * @return  The resulting string.
   */
  private static String listToMultiLineString(final List<String> l)
  {
    final StringBuilder buffer = new StringBuilder();
    for (final String s : l)
    {
      buffer.append(s);
      buffer.append(StaticUtils.EOL);
    }

    return buffer.toString();
  }
}
