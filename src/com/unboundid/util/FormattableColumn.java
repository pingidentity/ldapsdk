/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -67186391702592665L;



  // The alignment for this column.
  private final HorizontalAlignment alignment;

  // The width for this column.
  private final int width;

  // The lines that comprise the heading label for this column.
  private final String[] labelLines;



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
  public FormattableColumn(final int width, final HorizontalAlignment alignment,
                           final String... labelLines)
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
  public HorizontalAlignment getAlignment()
  {
    return alignment;
  }



  /**
   * Retrieves the lines to use as the label for this column.
   *
   * @return  The lines to use as the label for this column.
   */
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
  public void format(final StringBuilder buffer, final String text,
                     final OutputFormat format)
  {
    switch (format)
    {
      case TAB_DELIMITED_TEXT:
        buffer.append(text);
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
            buffer.append("\"\"");
            quotesNeeded = true;
          }
          else if ((c >= ' ') && (c <= '~'))
          {
            buffer.append(c);
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
   * Retrieves a string representation of this formattable column.
   *
   * @return  A string representation of this formattable column.
   */
  @Override()
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
  public void toString(final StringBuilder buffer)
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
