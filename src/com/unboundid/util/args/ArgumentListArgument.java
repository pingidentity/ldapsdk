/*
 * Copyright 2011-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2018 Ping Identity Corporation
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class defines an argument whose values are intended to be argument
 * strings as might be provided to a command-line application (e.g.,
 * "--arg1 arg1value --arg2 --arg3 arg3value").  Instances of this argument
 * will have their own argument parser that may be used to process the argument
 * strings.  This type of argument may not be particularly useful for use in
 * command-line applications, but may be used in other applications that may use
 * arguments in other ways.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ArgumentListArgument
       extends Argument
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1926330851837348378L;



  // The argument parser that will be used to validate values given for this
  // argument.
  private final ArgumentParser parser;

  // The list of argument parsers that correspond to values actually provided
  // to this argument.
  private final List<ArgumentParser> values;

  // The string representations of the values provided for this argument.
  private final List<String> valueStrings;



  /**
   * Creates a new argument list argument with the provided information.  It
   * will not be required, will permit at most one occurrence, and will use a
   * default placeholder.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  parser            The argument parser that will be used to
   *                           process values provided for this argument.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public ArgumentListArgument(final Character shortIdentifier,
                              final String longIdentifier,
                              final String description,
                              final ArgumentParser parser)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, false, 1, null, description, parser);
  }



  /**
   * Creates a new argument list argument with the provided information.
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
   * @param  parser            The argument parser that will be used to
   *                           process values provided for this argument.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public ArgumentListArgument(final Character shortIdentifier,
                              final String longIdentifier,
                              final boolean isRequired,
                              final int maxOccurrences,
                              final String valuePlaceholder,
                              final String description,
                              final ArgumentParser parser)
         throws ArgumentException
  {
    super(shortIdentifier, longIdentifier, isRequired, maxOccurrences,
         (valuePlaceholder == null)
              ? INFO_PLACEHOLDER_ARGS.get()
              : valuePlaceholder,
         description);

    this.parser = parser.getCleanCopy();

    values = new ArrayList<ArgumentParser>();
    valueStrings = new ArrayList<String>();
  }



  /**
   * Creates a new argument list argument that is a "clean" copy of the provided
   * source argument.
   *
   * @param  source  The source argument to use for this argument.
   */
  private ArgumentListArgument(final ArgumentListArgument source)
  {
    super(source);

    parser = source.parser;
    values = new ArrayList<ArgumentParser>();
    valueStrings = new ArrayList<String>();
  }



  /**
   * Retrieves a "clean" copy of the argument parser that will be used to
   * process values provided for this argument.
   *
   * @return  A "clean" copy of the argument parser that will be used to process
   *          values provided for this argument.
   */
  public ArgumentParser getCleanParser()
  {
    return parser.getCleanCopy();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addValue(final String valueString)
            throws ArgumentException
  {
    final List<String> argList;
    try
    {
      argList = StaticUtils.toArgumentList(valueString);
    }
    catch (final ParseException pe)
    {
      Debug.debugException(pe);
      throw new ArgumentException(ERR_ARG_LIST_MALFORMED_VALUE.get(valueString,
           getIdentifierString(), pe.getMessage()), pe);
    }

    final String[] args = new String[argList.size()];
    argList.toArray(args);

    final ArgumentParser p = parser.getCleanCopy();
    try
    {
      p.parse(args);
    }
    catch (final ArgumentException ae)
    {
      Debug.debugException(ae);
      throw new ArgumentException(ERR_ARG_LIST_INVALID_VALUE.get(valueString,
      getIdentifierString(), ae.getMessage()), ae);
    }

    values.add(p);
    valueStrings.add(valueString);
  }



  /**
   * Retrieves the list of argument parsers that have been used to process
   * values provided to this argument.
   *
   * @return  The list of argument parsers that have been used to process values
   *          provided to this argument.
   */
  public List<ArgumentParser> getValueParsers()
  {
    return Collections.unmodifiableList(values);
  }



  /**
   * Retrieves the list of the string representations of the values provided to
   * this argument.
   *
   * @return  The list of the string representations of the values provided to
   *          this argument.
   */
  public List<String> getValueStrings()
  {
    return Collections.unmodifiableList(valueStrings);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<String> getValueStringRepresentations(final boolean useDefault)
  {
    return Collections.unmodifiableList(valueStrings);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean hasDefaultValue()
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getDataTypeName()
  {
    return INFO_ARG_LIST_TYPE_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getValueConstraints()
  {
    return INFO_ARG_LIST_CONSTRAINTS.get();
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
  public ArgumentListArgument getCleanCopy()
  {
    return new ArgumentListArgument(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addToCommandLine(final List<String> argStrings)
  {
    if (valueStrings != null)
    {
      for (final String s : valueStrings)
      {
        argStrings.add(getIdentifierString());
        if (isSensitive())
        {
          argStrings.add("***REDACTED***");
        }
        else
        {
          argStrings.add(s);
        }
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ArgumentListArgument(");
    appendBasicToStringInfo(buffer);
    buffer.append(", parser=");
    parser.toString(buffer);
    buffer.append(')');
  }
}
