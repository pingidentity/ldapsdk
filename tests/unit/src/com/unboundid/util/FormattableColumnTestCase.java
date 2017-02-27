/*
 * Copyright 2009-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2017 UnboundID Corp.
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
 * This class provides test coverage for the {@code FormattableColumn} class.
 */
public class FormattableColumnTestCase
       extends UtilTestCase
{
  /**
   * Tests the behavior when a width of zero is provided.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testInvalidWidth()
  {
    new FormattableColumn(0, HorizontalAlignment.LEFT);
  }



  /**
   * Tests a column with no label lines.
   */
  @Test()
  public void testNoLabelLines()
  {
    FormattableColumn c = new FormattableColumn(10, HorizontalAlignment.LEFT);

    assertEquals(c.getWidth(), 10);

    assertEquals(c.getAlignment(), HorizontalAlignment.LEFT);

    assertNotNull(c.getLabelLines());
    assertEquals(c.getLabelLines().length, 0);

    assertNotNull(c.getSingleLabelLine());
    assertEquals(c.getSingleLabelLine(), "");

    assertNotNull(c.toString());
  }



  /**
   * Tests a column with a single label line.
   */
  @Test()
  public void testSingleLabelLine()
  {
    FormattableColumn c = new FormattableColumn(10, HorizontalAlignment.LEFT,
        "foo");

    assertEquals(c.getWidth(), 10);

    assertEquals(c.getAlignment(), HorizontalAlignment.LEFT);

    assertNotNull(c.getLabelLines());
    assertEquals(c.getLabelLines().length, 1);
    assertEquals(c.getLabelLines()[0], "foo");

    assertNotNull(c.getSingleLabelLine());
    assertEquals(c.getSingleLabelLine(), "foo");

    assertNotNull(c.toString());
  }



  /**
   * Tests a column with multiple label lines.
   */
  @Test()
  public void testMultipleLabelLines()
  {
    FormattableColumn c = new FormattableColumn(10, HorizontalAlignment.LEFT,
        "foo", "bar", "baz");

    assertEquals(c.getWidth(), 10);

    assertEquals(c.getAlignment(), HorizontalAlignment.LEFT);

    assertNotNull(c.getLabelLines());
    assertEquals(c.getLabelLines().length, 3);
    assertEquals(c.getLabelLines()[0], "foo");
    assertEquals(c.getLabelLines()[1], "bar");
    assertEquals(c.getLabelLines()[2], "baz");

    assertNotNull(c.getSingleLabelLine());
    assertEquals(c.getSingleLabelLine(), "foo bar baz");

    assertNotNull(c.toString());
  }



  /**
   * Tests the {@code format} method using empty strings.
   */
  @Test()
  public void testFormatEmptyStrings()
  {
    FormattableColumn c = new FormattableColumn(5, HorizontalAlignment.LEFT);
    StringBuilder buffer = new StringBuilder();

    c.format(buffer, "", OutputFormat.TAB_DELIMITED_TEXT);
    buffer.append('\t');
    c.format(buffer, "", OutputFormat.TAB_DELIMITED_TEXT);
    buffer.append('\t');
    c.format(buffer, "", OutputFormat.TAB_DELIMITED_TEXT);
    assertEquals(buffer.toString(), "\t\t");

    buffer = new StringBuilder();
    c.format(buffer, "", OutputFormat.CSV);
    buffer.append(',');
    c.format(buffer, "", OutputFormat.CSV);
    buffer.append(',');
    c.format(buffer, "", OutputFormat.CSV);
    assertEquals(buffer.toString(), ",,");

    buffer = new StringBuilder();
    c.format(buffer, "", OutputFormat.COLUMNS);
    buffer.append('|');
    c.format(buffer, "", OutputFormat.COLUMNS);
    buffer.append('|');
    c.format(buffer, "", OutputFormat.COLUMNS);
    assertEquals(buffer.toString(), "     |     |     ");
  }



  /**
   * Tests the {@code format} method using non-empty strings.
   */
  @Test()
  public void testFormatNonEmptyStrings()
  {
    FormattableColumn c = new FormattableColumn(5, HorizontalAlignment.LEFT);
    StringBuilder buffer = new StringBuilder();

    c.format(buffer, "abc", OutputFormat.TAB_DELIMITED_TEXT);
    buffer.append('\t');
    c.format(buffer, "defg", OutputFormat.TAB_DELIMITED_TEXT);
    buffer.append('\t');
    c.format(buffer, "hijkl", OutputFormat.TAB_DELIMITED_TEXT);
    assertEquals(buffer.toString(), "abc\tdefg\thijkl");

    buffer = new StringBuilder();
    c.format(buffer, "abc", OutputFormat.CSV);
    buffer.append(',');
    c.format(buffer, "defg", OutputFormat.CSV);
    buffer.append(',');
    c.format(buffer, "hijkl", OutputFormat.CSV);
    assertEquals(buffer.toString(), "abc,defg,hijkl");

    buffer = new StringBuilder();
    c.format(buffer, "abc", OutputFormat.COLUMNS);
    buffer.append('|');
    c.format(buffer, "defg", OutputFormat.COLUMNS);
    buffer.append('|');
    c.format(buffer, "hijkl", OutputFormat.COLUMNS);
    assertEquals(buffer.toString(), "abc  |defg |hijkl");
  }



  /**
   * Tests the {@code format} method using strings longer than the width.
   */
  @Test()
  public void testFormatLongStrings()
  {
    FormattableColumn c = new FormattableColumn(5, HorizontalAlignment.LEFT);
    StringBuilder buffer = new StringBuilder();

    c.format(buffer, "abcdef", OutputFormat.TAB_DELIMITED_TEXT);
    buffer.append('\t');
    c.format(buffer, "ghijkl", OutputFormat.TAB_DELIMITED_TEXT);
    buffer.append('\t');
    c.format(buffer, "mnopqr", OutputFormat.TAB_DELIMITED_TEXT);
    assertEquals(buffer.toString(), "abcdef\tghijkl\tmnopqr");

    buffer = new StringBuilder();
    c.format(buffer, "abcdef", OutputFormat.CSV);
    buffer.append(',');
    c.format(buffer, "ghijkl", OutputFormat.CSV);
    buffer.append(',');
    c.format(buffer, "mnopqr", OutputFormat.CSV);
    assertEquals(buffer.toString(), "abcdef,ghijkl,mnopqr");

    buffer = new StringBuilder();
    c.format(buffer, "abcdef", OutputFormat.COLUMNS);
    buffer.append(' ');
    c.format(buffer, "ghijkl", OutputFormat.COLUMNS);
    buffer.append(' ');
    c.format(buffer, "mnopqr", OutputFormat.COLUMNS);
    assertEquals(buffer.toString(), "abcde ghijk mnopq");
  }



  /**
   * Tests the {@code format} method using strings that require special CSV
   * formatting.
   */
  @Test()
  public void testFormatCSVQuotedStrings()
  {
    FormattableColumn c = new FormattableColumn(5, HorizontalAlignment.LEFT);
    StringBuilder buffer = new StringBuilder();

    c.format(buffer, ",", OutputFormat.TAB_DELIMITED_TEXT);
    buffer.append('\t');
    c.format(buffer, "\"", OutputFormat.TAB_DELIMITED_TEXT);
    buffer.append('\t');
    c.format(buffer, "\",\"", OutputFormat.TAB_DELIMITED_TEXT);
    assertEquals(buffer.toString(), ",\t\"\t\",\"");

    buffer = new StringBuilder();
    c.format(buffer, ",", OutputFormat.CSV);
    buffer.append(',');
    c.format(buffer, "\"", OutputFormat.CSV);
    buffer.append(',');
    c.format(buffer, "\",\"", OutputFormat.CSV);
    assertEquals(buffer.toString(), "\",\",\"\"\"\",\"\"\",\"\"\"");

    buffer = new StringBuilder();
    c.format(buffer, ",", OutputFormat.COLUMNS);
    buffer.append('-');
    c.format(buffer, "\"", OutputFormat.COLUMNS);
    buffer.append('-');
    c.format(buffer, "\",\"", OutputFormat.COLUMNS);
    assertEquals(buffer.toString(), ",    -\"    -\",\"  ");
  }
}
