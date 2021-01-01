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
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.SimpleDateFormat;
import java.util.Date;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a utility for formatting output in multiple columns.
 * Each column will have a defined width and alignment.  It can alternately
 * generate output as tab-delimited text or comma-separated values (CSV).
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ColumnFormatter
       implements Serializable
{
  /**
   * The symbols to use for special characters that might be encountered when
   * using a decimal formatter.
   */
  @NotNull private static final DecimalFormatSymbols DECIMAL_FORMAT_SYMBOLS =
       new DecimalFormatSymbols();
  static
  {
    DECIMAL_FORMAT_SYMBOLS.setInfinity("inf");
    DECIMAL_FORMAT_SYMBOLS.setNaN("NaN");
  }



  /**
   * The default output format to use.
   */
  @NotNull private static final OutputFormat DEFAULT_OUTPUT_FORMAT =
       OutputFormat.COLUMNS;



  /**
   * The default spacer to use between columns.
   */
  @NotNull private static final String DEFAULT_SPACER = " ";



  /**
   * The default date format string that will be used for timestamps.
   */
  @NotNull private static final String DEFAULT_TIMESTAMP_FORMAT = "HH:mm:ss";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2524398424293401200L;



  // Indicates whether to insert a timestamp before the first column.
  private final boolean includeTimestamp;

  // The column to use for the timestamp.
  @Nullable private final FormattableColumn timestampColumn;

  // The columns to be formatted.
  @NotNull private final FormattableColumn[] columns;

  // The output format to use.
  @NotNull private final OutputFormat outputFormat;

  // The string to insert between columns.
  @NotNull private final String spacer;

  // The format string to use for the timestamp.
  @NotNull private final String timestampFormat;

  // The thread-local formatter to use for floating-point values.
  @NotNull private final transient ThreadLocal<DecimalFormat> decimalFormatter;

  // The thread-local formatter to use when formatting timestamps.
  @NotNull private final transient ThreadLocal<SimpleDateFormat>
       timestampFormatter;



  /**
   * Creates a column formatter that will format the provided columns with the
   * default settings.
   *
   * @param  columns  The columns to be formatted.  At least one column must be
   *                  provided.
   */
  public ColumnFormatter(@NotNull final FormattableColumn... columns)
  {
    this(false, null, null, null, columns);
  }



  /**
   * Creates a column formatter that will format the provided columns.
   *
   * @param  includeTimestamp  Indicates whether to insert a timestamp before
   *                           the first column when generating data lines
   * @param  timestampFormat   The format string to use for the timestamp.  It
   *                           may be {@code null} if no timestamp should be
   *                           included or the default format should be used.
   *                           If a format is provided, then it should be one
   *                           that will always generate timestamps with a
   *                           constant width.
   * @param  outputFormat      The output format to use.
   * @param  spacer            The spacer to use between columns.  It may be
   *                           {@code null} if the default spacer should be
   *                           used.  This will only apply for an output format
   *                           of {@code COLUMNS}.
   * @param  columns           The columns to be formatted.  At least one
   *                           column must be provided.
   */
  public ColumnFormatter(final boolean includeTimestamp,
                         @Nullable final String timestampFormat,
                         @Nullable final OutputFormat outputFormat,
                         @Nullable final String spacer,
                         @NotNull final FormattableColumn... columns)
  {
    Validator.ensureNotNull(columns);
    Validator.ensureTrue(columns.length > 0);

    this.includeTimestamp = includeTimestamp;
    this.columns          = columns;

    decimalFormatter   = new ThreadLocal<>();
    timestampFormatter = new ThreadLocal<>();

    if (timestampFormat == null)
    {
      this.timestampFormat = DEFAULT_TIMESTAMP_FORMAT;
    }
    else
    {
      this.timestampFormat = timestampFormat;
    }

    if (outputFormat == null)
    {
      this.outputFormat = DEFAULT_OUTPUT_FORMAT;
    }
    else
    {
      this.outputFormat = outputFormat;
    }

    if (spacer == null)
    {
      this.spacer = DEFAULT_SPACER;
    }
    else
    {
      this.spacer = spacer;
    }

    if (includeTimestamp)
    {
      final SimpleDateFormat dateFormat =
           new SimpleDateFormat(this.timestampFormat);
      final String timestamp = dateFormat.format(new Date());
      final String label = INFO_COLUMN_LABEL_TIMESTAMP.get();
      final int width = Math.max(label.length(), timestamp.length());

      timestampFormatter.set(dateFormat);
      timestampColumn =
           new FormattableColumn(width, HorizontalAlignment.LEFT, label);
    }
    else
    {
      timestampColumn = null;
    }
  }



  /**
   * Indicates whether timestamps will be included in the output.
   *
   * @return  {@code true} if timestamps should be included, or {@code false}
   *          if not.
   */
  public boolean includeTimestamps()
  {
    return includeTimestamp;
  }



  /**
   * Retrieves the format string that will be used for generating timestamps.
   *
   * @return  The format string that will be used for generating timestamps.
   */
  @NotNull()
  public String getTimestampFormatString()
  {
    return timestampFormat;
  }



  /**
   * Retrieves the output format that will be used.
   *
   * @return  The output format for this formatter.
   */
  @NotNull()
  public OutputFormat getOutputFormat()
  {
    return outputFormat;
  }



  /**
   * Retrieves the spacer that will be used between columns.
   *
   * @return  The spacer that will be used between columns.
   */
  @NotNull()
  public String getSpacer()
  {
    return spacer;
  }



  /**
   * Retrieves the set of columns for this formatter.
   *
   * @return  The set of columns for this formatter.
   */
  @NotNull()
  public FormattableColumn[] getColumns()
  {
    final FormattableColumn[] copy = new FormattableColumn[columns.length];
    System.arraycopy(columns, 0, copy, 0, columns.length);
    return copy;
  }



  /**
   * Obtains the lines that should comprise the column headers.
   *
   * @param  includeDashes  Indicates whether to include a row of dashes below
   *                        the headers if appropriate for the output format.
   *
   * @return  The lines that should comprise the column headers.
   */
  @NotNull()
  public String[] getHeaderLines(final boolean includeDashes)
  {
    if (outputFormat == OutputFormat.COLUMNS)
    {
      int maxColumns = 1;
      final String[][] headerLines = new String[columns.length][];
      for (int i=0; i < columns.length; i++)
      {
        headerLines[i] = columns[i].getLabelLines();
        maxColumns = Math.max(maxColumns, headerLines[i].length);
      }

      final StringBuilder[] buffers = new StringBuilder[maxColumns];
      for (int i=0; i < maxColumns; i++)
      {
        final StringBuilder buffer = new StringBuilder();
        buffers[i] = buffer;
        if (includeTimestamp)
        {
          if (i == (maxColumns - 1))
          {
            timestampColumn.format(buffer, timestampColumn.getSingleLabelLine(),
                 outputFormat);
          }
          else
          {
            timestampColumn.format(buffer, "", outputFormat);
          }
        }

        for (int j=0; j < columns.length; j++)
        {
          if (includeTimestamp || (j > 0))
          {
            buffer.append(spacer);
          }

          final int rowNumber = i + headerLines[j].length - maxColumns;
          if (rowNumber < 0)
          {
            columns[j].format(buffer, "", outputFormat);
          }
          else
          {
            columns[j].format(buffer, headerLines[j][rowNumber], outputFormat);
          }
        }
      }

      final String[] returnArray;
      if (includeDashes)
      {
        returnArray = new String[maxColumns+1];
      }
      else
      {
        returnArray = new String[maxColumns];
      }

      for (int i=0; i < maxColumns; i++)
      {
        returnArray[i] = buffers[i].toString();
      }

      if (includeDashes)
      {
        final StringBuilder buffer = new StringBuilder();
        if (timestampColumn != null)
        {
          for (int i=0; i < timestampColumn.getWidth(); i++)
          {
            buffer.append('-');
          }
        }

        for (int i=0; i < columns.length; i++)
        {
          if (includeTimestamp || (i > 0))
          {
            buffer.append(spacer);
          }

          for (int j=0; j < columns[i].getWidth(); j++)
          {
            buffer.append('-');
          }
        }

        returnArray[returnArray.length - 1] = buffer.toString();
      }

      return returnArray;
    }
    else
    {
      final StringBuilder buffer = new StringBuilder();
      if (timestampColumn != null)
      {
        timestampColumn.format(buffer, timestampColumn.getSingleLabelLine(),
             outputFormat);
      }

      for (int i=0; i < columns.length; i++)
      {
        if (includeTimestamp || (i > 0))
        {
          if (outputFormat == OutputFormat.TAB_DELIMITED_TEXT)
          {
            buffer.append('\t');
          }
          else if (outputFormat == OutputFormat.CSV)
          {
            buffer.append(',');
          }
        }

        final FormattableColumn c = columns[i];
        c.format(buffer, c.getSingleLabelLine(), outputFormat);
      }

      return new String[] { buffer.toString() };
    }
  }



  /**
   * Formats a row of data.  The provided data must correspond to the columns
   * used when creating this formatter.
   *
   * @param  columnData  The elements to include in each row of the data.
   *
   * @return  A string containing the formatted row.
   */
  @NotNull()
  public String formatRow(@NotNull final Object... columnData)
  {
    final StringBuilder buffer = new StringBuilder();

    if (includeTimestamp)
    {
      SimpleDateFormat dateFormat = timestampFormatter.get();
      if (dateFormat == null)
      {
        dateFormat = new SimpleDateFormat(timestampFormat);
        timestampFormatter.set(dateFormat);
      }

      timestampColumn.format(buffer, dateFormat.format(new Date()),
           outputFormat);
    }

    for (int i=0; i < columns.length; i++)
    {
      if (includeTimestamp || (i > 0))
      {
        switch (outputFormat)
        {
          case TAB_DELIMITED_TEXT:
            buffer.append('\t');
            break;
          case CSV:
            buffer.append(',');
            break;
          case COLUMNS:
            buffer.append(spacer);
            break;
        }
      }

      if (i >= columnData.length)
      {
        columns[i].format(buffer, "", outputFormat);
      }
      else
      {
        columns[i].format(buffer, toString(columnData[i]), outputFormat);
      }
    }

    return buffer.toString();
  }



  /**
   * Retrieves a string representation of the provided object.  If the object
   * is {@code null}, then the empty string will be returned.  If the object is
   * a {@code Float} or {@code Double}, then it will be formatted using a
   * DecimalFormat with a format string of "0.000".  Otherwise, the
   * {@code String.valueOf} method will be used to obtain the string
   * representation.
   *
   * @param  o  The object for which to retrieve the string representation.
   *
   * @return  A string representation of the provided object.
   */
  @NotNull()
  private String toString(@Nullable final Object o)
  {
    if (o == null)
    {
      return "";
    }

    if ((o instanceof Float) || (o instanceof Double))
    {
      DecimalFormat f = decimalFormatter.get();
      if (f == null)
      {
        f = new DecimalFormat("0.000", DECIMAL_FORMAT_SYMBOLS);
        decimalFormatter.set(f);
      }

      final double d;
      if (o instanceof Float)
      {
        d = ((Float) o).doubleValue();
      }
      else
      {
        d = ((Double) o);
      }

      return f.format(d);
    }

    return String.valueOf(o);
  }
}
