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
package com.unboundid.util.args;



import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class defines an argument that is intended to hold one or more
 * timestamp values.  Values may be provided in any of the following formats:
 * <UL>
 *   <LI>Any valid generalized time format.</LI>
 *   <LI>A local time zone timestamp in the format YYYYMMDDhhmmss.uuu</LI>
 *   <LI>A local time zone timestamp in the format YYYYMMDDhhmmss</LI>
 *   <LI>A local time zone timestamp in the format YYYYMMDDhhmm</LI>
 * </UL>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class TimestampArgument
       extends Argument
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4842934851103696096L;



  // The argument value validators that have been registered for this argument.
  @NotNull private final List<ArgumentValueValidator> validators;

  // The list of default values for this argument.
  @Nullable private final List<Date> defaultValues;

  // The set of values assigned to this argument.
  @NotNull private final List<ObjectPair<Date,String>> values;



  /**
   * Creates a new timestamp argument with the provided information.  It will
   * not be required, will permit at most one occurrence, will use a default
   * placeholder, and will not have a default value.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public TimestampArgument(@Nullable final Character shortIdentifier,
                           @Nullable final String longIdentifier,
                           @NotNull final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, false, 1, null, description);
  }



  /**
   * Creates a new timestamp argument with the provided information.  It will
   * not have a default value.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  isRequired        Indicates whether this argument is required to
   *                           be provided.
   * @param  maxOccurrences    The maximum number of times this argument may be
   *                           provided on the command line.  A value less than
   *                           or equal to zero indicates that it may be present
   *                           any number of times.
   * @param  valuePlaceholder  A placeholder to display in usage information to
   *                           indicate that a value must be provided.  It may
   *                           be {@code null} if a default placeholder should
   *                           be used.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public TimestampArgument(@Nullable final Character shortIdentifier,
                           @Nullable final String longIdentifier,
                           final boolean isRequired, final int maxOccurrences,
                           @Nullable final String valuePlaceholder,
                           @NotNull final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         valuePlaceholder, description, (List<Date>) null);
  }



  /**
   * Creates a new timestamp argument with the provided information.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  isRequired        Indicates whether this argument is required to
   *                           be provided.
   * @param  maxOccurrences    The maximum number of times this argument may be
   *                           provided on the command line.  A value less than
   *                           or equal to zero indicates that it may be present
   *                           any number of times.
   * @param  valuePlaceholder  A placeholder to display in usage information to
   *                           indicate that a value must be provided.  It may
   *                           be {@code null} if a default placeholder should
   *                           be used.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  defaultValue      The default value to use for this argument if no
   *                           values were provided.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public TimestampArgument(@Nullable final Character shortIdentifier,
                           @Nullable final String longIdentifier,
                           final boolean isRequired, final int maxOccurrences,
                           @Nullable final String valuePlaceholder,
                           @NotNull final String description,
                           @Nullable final Date defaultValue)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired, maxOccurrences,
         valuePlaceholder, description,
         ((defaultValue == null)
              ? null
              : Collections.singletonList(defaultValue)));
  }



  /**
   * Creates a new timestamp argument with the provided information.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  isRequired        Indicates whether this argument is required to
   *                           be provided.
   * @param  maxOccurrences    The maximum number of times this argument may be
   *                           provided on the command line.  A value less than
   *                           or equal to zero indicates that it may be present
   *                           any number of times.
   * @param  valuePlaceholder  A placeholder to display in usage information to
   *                           indicate that a value must be provided.  It may
   *                           be {@code null} if a default placeholder should
   *                           be used.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  defaultValues     The set of default values to use for this
   *                           argument if no values were provided.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public TimestampArgument(@Nullable final Character shortIdentifier,
                           @Nullable final String longIdentifier,
                           final boolean isRequired, final int maxOccurrences,
                           @Nullable final String valuePlaceholder,
                           @NotNull final String description,
                           @Nullable final List<Date> defaultValues)
         throws ArgumentException
  {
    super(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         (valuePlaceholder == null)
              ? INFO_PLACEHOLDER_TIMESTAMP.get()
              : valuePlaceholder,
         description);

    if ((defaultValues == null) || defaultValues.isEmpty())
    {
      this.defaultValues = null;
    }
    else
    {
      this.defaultValues = Collections.unmodifiableList(defaultValues);
    }

    values = new ArrayList<>(5);
    validators = new ArrayList<>(5);
  }



  /**
   * Creates a new timestamp argument that is a "clean" copy of the provided
   * source argument.
   *
   * @param  source  The source argument to use for this argument.
   */
  private TimestampArgument(@NotNull final TimestampArgument source)
  {
    super(source);

    defaultValues = source.defaultValues;
    values        = new ArrayList<>(5);
    validators    = new ArrayList<>(source.validators);
  }



  /**
   * Retrieves the list of default values for this argument, which will be used
   * if no values were provided.
   *
   * @return   The list of default values for this argument, or {@code null} if
   *           there are no default values.
   */
  @Nullable()
  public List<Date> getDefaultValues()
  {
    return defaultValues;
  }



  /**
   * Updates this argument to ensure that the provided validator will be invoked
   * for any values provided to this argument.  This validator will be invoked
   * after all other validation has been performed for this argument.
   *
   * @param  validator  The argument value validator to be invoked.  It must not
   *                    be {@code null}.
   */
  public void addValueValidator(@NotNull final ArgumentValueValidator validator)
  {
    validators.add(validator);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addValue(@NotNull final String valueString)
            throws ArgumentException
  {
    final Date d;
    try
    {
      d = parseTimestamp(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ArgumentException(
           ERR_TIMESTAMP_VALUE_NOT_TIMESTAMP.get(valueString,
                getIdentifierString()),
           e);
    }


    if (values.size() >= getMaxOccurrences())
    {
      throw new ArgumentException(ERR_ARG_MAX_OCCURRENCES_EXCEEDED.get(
                                       getIdentifierString()));
    }

    for (final ArgumentValueValidator v : validators)
    {
      v.validateArgumentValue(this, valueString);
    }

    values.add(new ObjectPair<>(d, valueString));
  }



  /**
   * Parses the provided string as a timestamp using one of the supported
   * formats.
   *
   * @param  s  The string to parse as a timestamp.  It must not be
   *            {@code null}.
   *
   * @return  The {@code Date} object parsed from the provided timestamp.
   *
   * @throws  ParseException  If the provided string cannot be parsed as a
   *                          timestamp.
   */
  @NotNull()
  public static Date parseTimestamp(@NotNull final String s)
         throws ParseException
  {
    // First, try to parse the value as a generalized time.
    try
    {
      return StaticUtils.decodeGeneralizedTime(s);
    }
    catch (final Exception e)
    {
      // This is fine.  It just means the value isn't in the generalized time
      // format.
    }


    // See if the length of the string matches one of the supported local
    // formats.  If so, get a format string that we can use to parse the value.
    final String dateFormatString;
    switch (s.length())
    {
      case 18:
        dateFormatString = "yyyyMMddHHmmss.SSS";
        break;
      case 14:
        dateFormatString = "yyyyMMddHHmmss";
        break;
      case 12:
        dateFormatString = "yyyyMMddHHmm";
        break;
      default:
        throw new ParseException(ERR_TIMESTAMP_PARSE_ERROR.get(s), 0);
    }


    // Create a date formatter that will use the selected format string to parse
    // the timestamp.
    final SimpleDateFormat dateFormat = new SimpleDateFormat(dateFormatString);
    dateFormat.setLenient(false);
    return dateFormat.parse(s);
  }



  /**
   * Retrieves the value for this argument, or the default value if none was
   * provided.  If there are multiple values, then the first will be returned.
   *
   * @return  The value for this argument, or the default value if none was
   *          provided, or {@code null} if there is no value and no default
   *          value.
   */
  @Nullable()
  public Date getValue()
  {
    if (values.isEmpty())
    {
      if ((defaultValues == null) || defaultValues.isEmpty())
      {
        return null;
      }
      else
      {
        return defaultValues.get(0);
      }
    }
    else
    {
      return values.get(0).getFirst();
    }
  }



  /**
   * Retrieves the set of values for this argument.
   *
   * @return  The set of values for this argument.
   */
  @NotNull()
  public List<Date> getValues()
  {
    if (values.isEmpty() && (defaultValues != null))
    {
      return defaultValues;
    }

    final ArrayList<Date> dateList = new ArrayList<>(values.size());
    for (final ObjectPair<Date,String> p : values)
    {
      dateList.add(p.getFirst());
    }

    return Collections.unmodifiableList(dateList);
  }



  /**
   * Retrieves a string representation of the value for this argument, or a
   * string representation of the default value if none was provided.  If there
   * are multiple values, then the first will be returned.
   *
   * @return  The string representation of the value for this argument, or the
   *          string representation of the default value if none was provided,
   *          or {@code null} if there is no value and no default value.
   */
  @Nullable()
  public String getStringValue()
  {
    if (! values.isEmpty())
    {
      return values.get(0).getSecond();
    }

    if ((defaultValues != null) && (! defaultValues.isEmpty()))
    {
      return StaticUtils.encodeGeneralizedTime(defaultValues.get(0));
    }

    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getValueStringRepresentations(final boolean useDefault)
  {
    if (! values.isEmpty())
    {
      final ArrayList<String> valueStrings = new ArrayList<>(values.size());
      for (final ObjectPair<Date,String> p : values)
      {
        valueStrings.add(p.getSecond());
      }

      return Collections.unmodifiableList(valueStrings);
    }

    if (useDefault && (defaultValues != null) && (! defaultValues.isEmpty()))
    {
      final ArrayList<String> valueStrings =
           new ArrayList<>(defaultValues.size());
      for (final Date d : defaultValues)
      {
        valueStrings.add(StaticUtils.encodeGeneralizedTime(d));
      }

      return Collections.unmodifiableList(valueStrings);
    }

    return Collections.emptyList();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean hasDefaultValue()
  {
    return ((defaultValues != null) && (! defaultValues.isEmpty()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getDataTypeName()
  {
    return INFO_TIMESTAMP_TYPE_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getValueConstraints()
  {
    return INFO_TIMESTAMP_CONSTRAINTS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void reset()
  {
    super.reset();
    values.clear();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public TimestampArgument getCleanCopy()
  {
    return new TimestampArgument(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addToCommandLine(@NotNull final List<String> argStrings)
  {
    for (final ObjectPair<Date,String> p : values)
    {
      argStrings.add(getIdentifierString());
      if (isSensitive())
      {
        argStrings.add("***REDACTED***");
      }
      else
      {
        argStrings.add(p.getSecond());
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("TimestampArgument(");
    appendBasicToStringInfo(buffer);

    if ((defaultValues != null) && (! defaultValues.isEmpty()))
    {
      if (defaultValues.size() == 1)
      {
        buffer.append(", defaultValue='");
        buffer.append(StaticUtils.encodeGeneralizedTime(defaultValues.get(0)));
      }
      else
      {
        buffer.append(", defaultValues={");

        final Iterator<Date> iterator = defaultValues.iterator();
        while (iterator.hasNext())
        {
          buffer.append('\'');
          buffer.append(StaticUtils.encodeGeneralizedTime(iterator.next()));
          buffer.append('\'');

          if (iterator.hasNext())
          {
            buffer.append(", ");
          }
        }

        buffer.append('}');
      }
    }

    buffer.append(')');
  }
}
