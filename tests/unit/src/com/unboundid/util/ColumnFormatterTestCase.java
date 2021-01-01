/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.util;



import org.testng.annotations.Test;



/**
 * This class provides test coverage for the {@code ColumnFormatter} class.
 */
public class ColumnFormatterTestCase
       extends UtilTestCase
{
  /**
   * Provides test coverage for the default constructor with a single column.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultSingleColumn()
         throws Exception
  {
    ColumnFormatter f = new ColumnFormatter(
         new FormattableColumn(5, HorizontalAlignment.LEFT, "a"));

    assertNotNull(f);

    assertFalse(f.includeTimestamps());

    assertNotNull(f.getTimestampFormatString());

    assertNotNull(f.getOutputFormat());
    assertEquals(f.getOutputFormat(), OutputFormat.COLUMNS);

    assertNotNull(f.getSpacer());
    assertEquals(f.getSpacer(), " ");

    assertNotNull(f.getColumns());
    assertEquals(f.getColumns().length, 1);
    assertEquals(f.getColumns()[0].getSingleLabelLine(), "a");

    assertNotNull(f.getHeaderLines(false));
    assertEquals(f.getHeaderLines(false).length, 1);
    assertEquals(f.getHeaderLines(false)[0], "a    ");

    assertNotNull(f.getHeaderLines(true));
    assertEquals(f.getHeaderLines(true).length, 2);
    assertEquals(f.getHeaderLines(true)[0], "a    ");
    assertEquals(f.getHeaderLines(true)[1], "-----");

    assertEquals(f.formatRow((String) null), "     ");

    assertEquals(f.formatRow("a"), "a    ");
    assertEquals(f.formatRow("ab"), "ab   ");
    assertEquals(f.formatRow("abc"), "abc  ");
    assertEquals(f.formatRow("abcd"), "abcd ");
    assertEquals(f.formatRow("abcde"), "abcde");
    assertEquals(f.formatRow("abcdef"), "abcde");

    assertNotNull(f.formatRow(Integer.valueOf("1234")));
    assertEquals(f.formatRow(Integer.valueOf("1234")), "1234 ");

    assertNotNull(f.formatRow(Float.valueOf("1.234")));
    assertTrue(f.formatRow(Float.valueOf("1.234")).startsWith("1.23"));

    assertNotNull(f.formatRow(Double.valueOf("1.234")));
    assertTrue(f.formatRow(Double.valueOf("1.234")).startsWith("1.23"));
  }



  /**
   * Tests the behavior of the default constructor when no columns are provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testDefaultConstructorNoColumns()
         throws Exception
  {
    new ColumnFormatter();
  }



  /**
   * Tests the non-default constructor with non-{@code null} values for all
   * arguments and a tab-delimited format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonDefaultConstructorTabDelimited()
         throws Exception
  {
    ColumnFormatter f = new ColumnFormatter(true, "HH:mm:ss",
         OutputFormat.TAB_DELIMITED_TEXT, "|",
         new FormattableColumn(5, HorizontalAlignment.LEFT, "a"),
         new FormattableColumn(5, HorizontalAlignment.CENTER, "b"),
         new FormattableColumn(5, HorizontalAlignment.RIGHT, "c"));

    assertNotNull(f);

    assertTrue(f.includeTimestamps());

    assertNotNull(f.getTimestampFormatString());
    assertEquals(f.getTimestampFormatString(), "HH:mm:ss");

    assertNotNull(f.getOutputFormat());
    assertEquals(f.getOutputFormat(), OutputFormat.TAB_DELIMITED_TEXT);

    assertNotNull(f.getSpacer());
    assertEquals(f.getSpacer(), "|");

    assertNotNull(f.getColumns());
    assertEquals(f.getColumns().length, 3);

    assertNotNull(f.getHeaderLines(true));
    assertEquals(f.getHeaderLines(true).length, 1);
    assertEquals(f.getHeaderLines(true)[0], "Timestamp\ta\tb\tc");

    assertNotNull(f.formatRow(null, null, null));
    assertTrue(f.formatRow(null, null, null).endsWith("\t\t\t"));

    assertNotNull(f.formatRow("", "", ""));
    assertTrue(f.formatRow("", "", "").endsWith("\t\t\t"));

    assertNotNull(f.formatRow("a", "ab", "abc"));
    assertTrue(f.formatRow("a", "ab", "abc").endsWith("\ta\tab\tabc"));
  }



  /**
   * Tests the non-default constructor with non-{@code null} values for all
   * arguments and a CSV format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonDefaultConstructorCSV()
         throws Exception
  {
    ColumnFormatter f = new ColumnFormatter(false, "HH:mm:ss",
         OutputFormat.CSV, "|",
         new FormattableColumn(5, HorizontalAlignment.LEFT, "a", "1"),
         new FormattableColumn(5, HorizontalAlignment.CENTER, "b", "2"),
         new FormattableColumn(5, HorizontalAlignment.RIGHT, "c", "3"));

    assertNotNull(f);

    assertFalse(f.includeTimestamps());

    assertNotNull(f.getTimestampFormatString());
    assertEquals(f.getTimestampFormatString(), "HH:mm:ss");

    assertNotNull(f.getOutputFormat());
    assertEquals(f.getOutputFormat(), OutputFormat.CSV);

    assertNotNull(f.getSpacer());
    assertEquals(f.getSpacer(), "|");

    assertNotNull(f.getColumns());
    assertEquals(f.getColumns().length, 3);

    assertNotNull(f.getHeaderLines(true));
    assertEquals(f.getHeaderLines(true).length, 1);
    assertEquals(f.getHeaderLines(true)[0], "a 1,b 2,c 3");

    assertNotNull(f.formatRow(null, null, null));
    assertEquals(f.formatRow(null, null, null), ",,");

    assertNotNull(f.formatRow("", "", ""));
    assertEquals(f.formatRow("", "", ""), ",,");

    assertNotNull(f.formatRow("a", "ab", "abc"));
    assertEquals(f.formatRow("a", "ab", "abc"), "a,ab,abc");
  }



  /**
   * Tests the non-default constructor with non-{@code null} values for all
   * arguments and a columnar format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonDefaultConstructorColumns()
         throws Exception
  {
    ColumnFormatter f = new ColumnFormatter(true, "HH:mm:ss",
         OutputFormat.COLUMNS, "|",
         new FormattableColumn(5, HorizontalAlignment.LEFT, "a", "1"),
         new FormattableColumn(5, HorizontalAlignment.CENTER, "b", "2"),
         new FormattableColumn(5, HorizontalAlignment.RIGHT, "c", "3", "iii"));

    assertNotNull(f);

    assertTrue(f.includeTimestamps());

    assertNotNull(f.getTimestampFormatString());
    assertEquals(f.getTimestampFormatString(), "HH:mm:ss");

    assertNotNull(f.getOutputFormat());
    assertEquals(f.getOutputFormat(), OutputFormat.COLUMNS);

    assertNotNull(f.getSpacer());
    assertEquals(f.getSpacer(), "|");

    assertNotNull(f.getColumns());
    assertEquals(f.getColumns().length, 3);

    assertNotNull(f.getHeaderLines(true));
    assertEquals(f.getHeaderLines(true).length, 4);
    assertEquals(f.getHeaderLines(true)[0], "         |     |     |    c");
    assertEquals(f.getHeaderLines(true)[1], "         |a    |  b  |    3");
    assertEquals(f.getHeaderLines(true)[2], "Timestamp|1    |  2  |  iii");
    assertEquals(f.getHeaderLines(true)[3], "---------|-----|-----|-----");

    assertNotNull(f.formatRow(null, null, null));
    assertTrue(f.formatRow(null, null, null).endsWith("|     |     |     "));

    assertNotNull(f.formatRow("", "", ""));
    assertTrue(f.formatRow("", "", "").endsWith("|     |     |     "));

    assertNotNull(f.formatRow("a", "ab", "abc"));
    assertTrue(f.formatRow("a", "ab", "abc").endsWith("|a    | ab  |  abc"));

    assertNotNull(f.formatRow("a", "ab"));
    assertTrue(f.formatRow("a", "ab").endsWith("|a    | ab  |     "));
  }
}
