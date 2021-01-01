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



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class provides a data structure that represents a subcommand that can be
 * used in conjunction with the argument parser.  A subcommand can be used to
 * allow a single command to do multiple different things.  A subcommand is
 * represented in the argument list as a string that is not prefixed by any
 * dashes, and there can be at most one subcommand in the argument list.  Each
 * subcommand has its own argument parser that defines the arguments available
 * for use with that subcommand, and the tool still provides support for global
 * arguments that are not associated with any of the subcommands.
 * <BR><BR>
 * The use of subcommands imposes the following constraints on an argument
 * parser:
 * <UL>
 *   <LI>
 *     Each subcommand must be registered with the argument parser that defines
 *     the global arguments for the tool.  Subcommands cannot be registered with
 *     a subcommand's argument parser (i.e., you cannot have a subcommand with
 *     its own subcommands).
 *   </LI>
 *   <LI>
 *     There must not be any conflicts between the global arguments and the
 *     subcommand-specific arguments.  However, there can be conflicts between
 *     the arguments used across separate subcommands.
 *   </LI>
 *   <LI>
 *     If the global argument parser cannot support both unnamed subcommands and
 *     unnamed trailing arguments.
 *   </LI>
 *   <LI>
 *     Global arguments can exist anywhere in the argument list, whether before
 *     or after the subcommand.  Subcommand-specific arguments must only appear
 *     after the subcommand in the argument list.
 *   </LI>
 * </UL>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public final class SubCommand
{
  // The global argument parser with which this subcommand is associated.
  @Nullable private volatile ArgumentParser globalArgumentParser;

  // The argument parser for the arguments specific to this subcommand.
  @NotNull private final ArgumentParser subcommandArgumentParser;

  // Indicates whether this subcommand was provided in the set of command-line
  // arguments.
  private volatile boolean isPresent;

  // The set of example usages for this subcommand.
  @NotNull private final LinkedHashMap<String[],String> exampleUsages;

  // The names for this subcommand, mapped from an all-lowercase representation
  // to an object pair that has the name in the desired case and an indicate
  // as to whether the name is hidden.
  @NotNull private final Map<String,ObjectPair<String,Boolean>> names;

  // The description for this subcommand.
  @NotNull private final String description;



  /**
   * Creates a new subcommand with the provided information.
   *
   * @param  name           A name that may be used to reference this subcommand
   *                        in the argument list.  It must not be {@code null}
   *                        or empty, and it will be treated in a
   *                        case-insensitive manner.
   * @param  description    The description for this subcommand.  It must not be
   *                        {@code null}.
   * @param  parser         The argument parser that will be used to validate
   *                        the subcommand-specific arguments.  It must not be
   *                        {@code null}, it must not be configured with any
   *                        subcommands of its own, and it must not be
   *                        configured to allow unnamed trailing arguments.
   * @param  exampleUsages  An optional map correlating a complete set of
   *                        arguments that may be used when running the tool
   *                        with this subcommand (including the subcommand and
   *                        any appropriate global and/or subcommand-specific
   *                        arguments) and a description of the behavior with
   *                        that subcommand.
   *
   * @throws  ArgumentException  If there is a problem with the provided name,
   *                             description, or argument parser.
   */
  public SubCommand(@NotNull final String name,
                    @NotNull final String description,
                    @NotNull final ArgumentParser parser,
                    @NotNull final LinkedHashMap<String[],String> exampleUsages)
         throws ArgumentException
  {
    names = new LinkedHashMap<>(StaticUtils.computeMapCapacity(5));
    addName(name);

    this.description = description;
    if ((description == null) || description.isEmpty())
    {
      throw new ArgumentException(
           ERR_SUBCOMMAND_DESCRIPTION_NULL_OR_EMPTY.get());
    }

    subcommandArgumentParser = parser;
    if (parser == null)
    {
      throw new ArgumentException(ERR_SUBCOMMAND_PARSER_NULL.get());
    }
    else if (parser.allowsTrailingArguments())
    {
      throw new ArgumentException(
           ERR_SUBCOMMAND_PARSER_ALLOWS_TRAILING_ARGS.get());
    }
     else if (parser.hasSubCommands())
    {
      throw new ArgumentException(ERR_SUBCOMMAND_PARSER_HAS_SUBCOMMANDS.get());
    }

    if (exampleUsages == null)
    {
      this.exampleUsages =
           new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));
    }
    else
    {
      this.exampleUsages = new LinkedHashMap<>(exampleUsages);
    }

    isPresent = false;
    globalArgumentParser = null;
  }



  /**
   * Creates a new subcommand that is a "clean" copy of the provided source
   * subcommand.
   *
   * @param  source  The source subcommand to use for this subcommand.
   */
  private SubCommand(@NotNull final SubCommand source)
  {
    names = new LinkedHashMap<>(source.names);
    description = source.description;
    subcommandArgumentParser =
         new ArgumentParser(source.subcommandArgumentParser, this);
    exampleUsages = new LinkedHashMap<>(source.exampleUsages);
    isPresent = false;
    globalArgumentParser = null;
  }



  /**
   * Retrieves the primary name for this subcommand, which is the first name
   * that was assigned to it.
   *
   * @return  The primary name for this subcommand.
   */
  @NotNull()
  public String getPrimaryName()
  {
    return names.values().iterator().next().getFirst();
  }



  /**
   * Retrieves the list of all names, including hidden names, for this
   * subcommand.
   *
   * @return  The list of all names for this subcommand.
   */
  @NotNull()
  public List<String> getNames()
  {
    return getNames(true);
  }



  /**
   * Retrieves a list of the non-hidden names for this subcommand.
   *
   *
   * @param  includeHidden  Indicates whether to include hidden names in the
   *                        list that is returned.
   *
   * @return  A list of the non-hidden names for this subcommand.
   */
  @NotNull()
  public List<String> getNames(final boolean includeHidden)
  {
    final ArrayList<String> nameList = new ArrayList<>(names.size());
    for (final ObjectPair<String,Boolean> p : names.values())
    {
      if (includeHidden || (! p.getSecond()))
      {
        nameList.add(p.getFirst());
      }
    }

    return Collections.unmodifiableList(nameList);
  }



  /**
   * Indicates whether the provided name is assigned to this subcommand.
   *
   * @param  name  The name for which to make the determination.  It must not be
   *               {@code null}.
   *
   * @return  {@code true} if the provided name is assigned to this subcommand,
   *          or {@code false} if not.
   */
  public boolean hasName(@NotNull final String name)
  {
    return names.containsKey(StaticUtils.toLowerCase(name));
  }



  /**
   * Adds the provided name that may be used to reference this subcommand.  It
   * will not be hidden.
   *
   * @param  name  A name that may be used to reference this subcommand in the
   *               argument list.  It must not be {@code null} or empty, and it
   *               will be treated in a case-insensitive manner.
   *
   * @throws  ArgumentException  If the provided name is already registered with
   *                             this subcommand, or with another subcommand
   *                             also registered with the global argument
   *                             parser.
   */
  public void addName(@NotNull final String name)
         throws ArgumentException
  {
    addName(name, false);
  }



  /**
   * Adds the provided name that may be used to reference this subcommand.
   *
   * @param  name      A name that may be used to reference this subcommand in
   *                   the argument list.  It must not be {@code null} or empty,
   *                   and it will be treated in a case-insensitive manner.
   * @param  isHidden  Indicates whether the provided name should be hidden.  A
   *                   hidden name may be used to invoke this subcommand but
   *                   will not be displayed in usage information.
   *
   * @throws  ArgumentException  If the provided name is already registered with
   *                             this subcommand, or with another subcommand
   *                             also registered with the global argument
   *                             parser.
   */
  public void addName(@NotNull final String name, final boolean isHidden)
         throws ArgumentException
  {
    if ((name == null) || name.isEmpty())
    {
      throw new ArgumentException(ERR_SUBCOMMAND_NAME_NULL_OR_EMPTY.get());
    }

    final String lowerName = StaticUtils.toLowerCase(name);
    if (names.containsKey(lowerName))
    {
      throw new ArgumentException(ERR_SUBCOMMAND_NAME_ALREADY_IN_USE.get(name));
    }

    if (globalArgumentParser != null)
    {
      globalArgumentParser.addSubCommand(name, this);
    }

    names.put(lowerName, new ObjectPair<>(name, isHidden));
  }



  /**
   * Retrieves the description for this subcommand.
   *
   * @return  The description for this subcommand.
   */
  @NotNull()
  public String getDescription()
  {
    return description;
  }



  /**
   * Retrieves the argument parser that will be used to process arguments
   * specific to this subcommand.
   *
   * @return  The argument parser that will be used to process arguments
   *          specific to this subcommand.
   */
  @NotNull()
  public ArgumentParser getArgumentParser()
  {
    return subcommandArgumentParser;
  }



  /**
   * Indicates whether this subcommand was provided in the set of command-line
   * arguments.
   *
   * @return  {@code true} if this subcommand was provided in the set of
   *          command-line arguments, or {@code false} if not.
   */
  public boolean isPresent()
  {
    return isPresent;
  }



  /**
   * Indicates that this subcommand was provided in the set of command-line
   * arguments.
   */
  void setPresent()
  {
    isPresent = true;
  }



  /**
   * Retrieves the global argument parser with which this subcommand is
   * registered.
   *
   * @return  The global argument parser with which this subcommand is
   *          registered.
   */
  @Nullable()
  ArgumentParser getGlobalArgumentParser()
  {
    return globalArgumentParser;
  }



  /**
   * Sets the global argument parser for this subcommand.
   *
   * @param  globalArgumentParser  The global argument parser for this
   *                               subcommand.
   */
  void setGlobalArgumentParser(
            @NotNull final ArgumentParser globalArgumentParser)
  {
    this.globalArgumentParser = globalArgumentParser;
  }



  /**
   * Retrieves a set of information that may be used to generate example usage
   * information when the tool is run with this subcommand.  Each element in the
   * returned map should consist of a map between an example set of arguments
   * (including the subcommand name) and a string that describes the behavior of
   * the tool when invoked with that set of arguments.
   *
   * @return  A set of information that may be used to generate example usage
   *          information, or an empty map if no example usages are available.
   */
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    return exampleUsages;
  }



  /**
   * Creates a copy of this subcommand that is "clean" and appears as if it has
   * not been used to parse an argument set.  The new subcommand will have all
   * of the same names and argument constraints as this subcommand.
   *
   * @return  The "clean" copy of this subcommand.
   */
  @NotNull()
  public SubCommand getCleanCopy()
  {
    return new SubCommand(this);
  }



  /**
   * Retrieves a string representation of this subcommand.
   *
   * @return  A string representation of this subcommand.
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
   * Appends a string representation of this subcommand to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SubCommand(");

    if (names.size() == 1)
    {
      buffer.append("name='");
      buffer.append(names.values().iterator().next());
      buffer.append('\'');
    }
    else
    {
      buffer.append("names={");

      final Iterator<ObjectPair<String,Boolean>> iterator =
           names.values().iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next().getFirst());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(", ");
        }
      }

      buffer.append('}');
    }

    buffer.append(", description='");
    buffer.append(description);
    buffer.append("', parser=");
    subcommandArgumentParser.toString(buffer);
    buffer.append(')');
  }
}
