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



import java.io.Serializable;



/**
 * This class provides a data structure with information about a column to use
 * with the {@link ColumnFormatter}.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FormattableColumn
       implements Serializable
{
  /**
   * A system property that can be used to specify what character should be used
   * when escaping quotation marks in the output.  If set, the value of the
   * property should be a single character, and it is recommended to be either
   * the double quote character or the backslash character.
   */
  @NotNull public static final String CSV_QUOTE_ESCAPE_CHARACTER_PROPERTY =
       FormattableColumn.class.getName() + ".csvQuoteEscapeCharacter";



  /**
   * The character that should be used to escape quotation marks in
   * CSV-formatted output.  RFC 4180 says it should be a double quote (so that
   * '"' will be escaped as '""'), but we have used a backslash for this purpose
   * in the past.  We'll use the quote to be standards-compliant, but will allow
   * it to be overridden with a system property.
   */
  private static volatile char CSV_QUOTE_ESCAPE_CHARACTER;
  static
  {
    char escapeCharacter = '"';
    final String propertyValue =
         StaticUtils.getSystemProperty(CSV_QUOTE_ESCAPE_CHARACTER_PROPERTY);
    if ((propertyValue != null) && (propertyValue.length() == 1))
    {
      escapeCharacter = propertyValue.charAt(0);
    }

    CSV_QUOTE_ESCAPE_CHARACTER = escapeCharacter;
  }



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -67186391702592665L;



  // The alignment for this column.
  @NotNull private final HorizontalAlignment alignment;

  // The width for this column.
  private final int width;

  // The lines that comprise the heading label for this column.
  @NotNull private final String[] labelLines;



  /**
   * Creates a new formattable column with the provided information.
   *
   * @param  width       The width to use for this column.  It must be greater
   *                     than or equal to 1.
   * @param  alignment   The alignment to use for this column.  It must not be
   *                     {@code null}.
   * @param  labelLines  The lines to use as the label for this column.  It must
   *                     not be {@code null}.
   */
  public FormattableColumn(final int width,
                           @NotNull final HorizontalAlignment alignment,
                           @NotNull final String... labelLines)
  {
    Validator.ensureTrue(width >= 1);
    Validator.ensureNotNull(alignment, labelLines);

    this.width      = width;
    this.alignment  = alignment;
    this.labelLines = labelLines;
  }



  /**
   * Retrieves the width for this column.
   *
   * @return  The width for this column.
   */
  public int getWidth()
  {
    return width;
  }



  /**
   * Retrieves the alignment for this column.
   *
   * @return  The alignment for this column.
   */
  @NotNull()
  public HorizontalAlignment getAlignment()
  {
    return alignment;
  }



  /**
   * Retrieves the lines to use as the label for this column.
   *
   * @return  The lines to use as the label for this column.
   */
  @NotNull()
  public String[] getLabelLines()
  {
    return labelLines;
  }



  /**
   * Retrieves a single-line representation of the label.  If there are multiple
   * header lines, then they will be concatenated and separated by a space.
   *
   * @return  A single-line representation of the label.
   */
  @NotNull()
  public String getSingleLabelLine()
  {
    switch (labelLines.length)
    {
      case 0:
        return "";
      case 1:
        return labelLines[0];
      default:
        final StringBuilder buffer = new StringBuilder();
        buffer.append(labelLines[0]);
        for (int i=1; i < labelLines.length; i++)
        {
          buffer.append(' ');
          buffer.append(labelLines[i]);
        }
        return buffer.toString();
    }
  }



  /**
   * Appends a formatted representation of the provided text to the given
   * buffer.
   *
   * @param  buffer  The buffer to which the text should be appended.  It must
   *                 not be {@code null}.
   * @param  text    The text to append to the buffer.  It must not be
   *                 {@code null}.
   * @param  format  The format to use for the text.  It must not be
   *                 {@code null}.
   */
  public void format(@NotNull final StringBuilder buffer,
                     @NotNull final String text,
                     @NotNull final OutputFormat format)
  {
    switch (format)
    {
      case TAB_DELIMITED_TEXT:
        for (int i=0; i < text.length(); i++)
        {
          final char c = text.charAt(i);
          switch (c)
          {
            case '\t':
              buffer.append("\\t");
              break;
            case '\r':
              buffer.append("\\r");
              break;
            case '\n':
              buffer.append("\\n");
              break;
            case '\\':
              buffer.append("\\\\");
              break;
            default:
              buffer.append(c);
              break;
          }
        }
        break;

      case CSV:
        boolean quotesNeeded = false;
        final int length = text.length();
        final int startPos = buffer.length();
        for (int i=0; i < length; i++)
        {
          final char c = text.charAt(i);
          if (c == ',')
          {
            buffer.append(',');
            quotesNeeded = true;
          }
          else if (c == '"')
          {
            buffer.append(CSV_QUOTE_ESCAPE_CHARACTER);
            buffer.append(c);
            quotesNeeded = true;
          }
          else if (c == CSV_QUOTE_ESCAPE_CHARACTER)
          {
            buffer.append(c);
            buffer.append(c);
            quotesNeeded = true;
          }
          else if (c == '\\')
          {
            buffer.append(c);
            quotesNeeded = true;
          }
          else if ((c >= ' ') && (c <= '~'))
          {
            buffer.append(c);
          }
          else
          {
            buffer.append(c);
            quotesNeeded = true;
          }
        }

        if (quotesNeeded)
        {
          buffer.insert(startPos, '"');
          buffer.append('"');
        }
        break;

      case COLUMNS:
        alignment.format(buffer, text, width);
        break;
    }
  }



  /**
   * Specifies the character that should be used to escape the double quote
   * character in CSV-formatted values.  RFC 4180 states that it should be a
   * double quote character (that is, a single double quote should be formatted
   * as '""'), and that is now the default behavior, but the LDAP SDK formerly
   * used a backslash as an escape character (like '\"'), and this method can be
   * used to restore that behavior if desired.  Alternatively, this can be
   * accomplished without any change to the application source code by launching
   * the JVM with the
   * {@code com.unboundid.util.FormattableColumn.csvQuoteEscapeCharacter} system
   * property set to a value that contains only the backslash character.
   *
   * @param  c  The character to use to escape the double quote character in
   *            CSV-formatted values.  This is only recommended to be the
   *            double quote character or the backslash character.
   */
  public static void setCSVQuoteEscapeCharacter(final char c)
  {
    CSV_QUOTE_ESCAPE_CHARACTER = c;
  }



  /**
   * Retrieves a string representation of this formattable column.
   *
   * @return  A string representation of this formattable column.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this formattable column to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("FormattableColumn(width=");
    buffer.append(width);
    buffer.append(", alignment=");
    buffer.append(alignment);
    buffer.append(", label=\"");
    buffer.append(getSingleLabelLine());
    buffer.append("\")");
  }
}
