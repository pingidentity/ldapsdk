/*
 * Copyright 2008-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2014 UnboundID Corp.
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



import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

import com.unboundid.util.Debug;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;
import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class provides an argument parser, which may be used to process command
 * line arguments provided to Java applications.  See the package-level Javadoc
 * documentation for details regarding the capabilities of the argument parser.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ArgumentParser
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 361008526269946465L;



  // The maximum number of trailing arguments allowed to be provided.
  private final int maxTrailingArgs;

  // The set of named arguments associated with this parser, indexed by short
  // identifier.
  private final LinkedHashMap<Character,Argument> namedArgsByShortID;

  // The set of named arguments associated with this parser, indexed by long
  // identifier.
  private final LinkedHashMap<String,Argument> namedArgsByLongID;

  // The full set of named arguments associated with this parser.
  private final List<Argument> namedArgs;

  // Sets of arguments in which if the key argument is provided, then at least
  // one of the value arguments must also be provided.
  private final List<ObjectPair<Argument,Set<Argument>>> dependentArgumentSets;

  // Sets of arguments in which at most one argument in the list is allowed to
  // be present.
  private final List<Set<Argument>> exclusiveArgumentSets;

  // Sets of arguments in which at least one argument in the list is required to
  // be present.
  private final List<Set<Argument>> requiredArgumentSets;

  // The list of trailing arguments provided on the command line.
  private final List<String> trailingArgs;

  // The description for the associated command.
  private final String commandDescription;

  // The name for the associated command.
  private final String commandName;

  // The placeholder string for the trailing arguments.
  private final String trailingArgsPlaceholder;



  /**
   * Creates a new instance of this argument parser with the provided
   * information.  It will not allow unnamed trailing arguments.
   *
   * @param  commandName         The name of the application or utility with
   *                             which this argument parser is associated.  It
   *                             must not be {@code null}.
   * @param  commandDescription  A description of the application or utility
   *                             with which this argument parser is associated.
   *                             It will be included in generated usage
   *                             information.  It must not be {@code null}.
   *
   * @throws  ArgumentException  If either the command name or command
   *                             description is {@code null},
   */
  public ArgumentParser(final String commandName,
                        final String commandDescription)
         throws ArgumentException
  {
    this(commandName, commandDescription, 0, null);
  }



  /**
   * Creates a new instance of this argument parser with the provided
   * information.
   *
   * @param  commandName              The name of the application or utility
   *                                  with which this argument parser is
   *                                  associated.  It must not be {@code null}.
   * @param  commandDescription       A description of the application or
   *                                  utility with which this argument parser is
   *                                  associated.  It will be included in
   *                                  generated usage information.  It must not
   *                                  be {@code null}.
   * @param  maxTrailingArgs          The maximum number of trailing arguments
   *                                  that may be provided to this command.  A
   *                                  value of zero indicates that no trailing
   *                                  arguments will be allowed.  A value less
   *                                  than zero will indicate that there is no
   *                                  limit on the number of trailing arguments
   *                                  allowed.
   * @param  trailingArgsPlaceholder  A placeholder string that will be included
   *                                  in usage output to indicate what trailing
   *                                  arguments may be provided.  It must not be
   *                                  {@code null} if {@code maxTrailingArgs} is
   *                                  anything other than zero.
   *
   * @throws  ArgumentException  If either the command name or command
   *                             description is {@code null}, or if the maximum
   *                             number of trailing arguments is non-zero and
   *                             the trailing arguments placeholder is
   *                             {@code null}.
   */
  public ArgumentParser(final String commandName,
                        final String commandDescription,
                        final int maxTrailingArgs,
                        final String trailingArgsPlaceholder)
         throws ArgumentException
  {
    if (commandName == null)
    {
      throw new ArgumentException(ERR_PARSER_COMMAND_NAME_NULL.get());
    }

    if (commandDescription == null)
    {
      throw new ArgumentException(ERR_PARSER_COMMAND_DESCRIPTION_NULL.get());
    }

    if ((maxTrailingArgs != 0) && (trailingArgsPlaceholder == null))
    {
      throw new ArgumentException(
                     ERR_PARSER_TRAILING_ARGS_PLACEHOLDER_NULL.get());
    }

    this.commandName             = commandName;
    this.commandDescription      = commandDescription;
    this.trailingArgsPlaceholder = trailingArgsPlaceholder;

    if (maxTrailingArgs >= 0)
    {
      this.maxTrailingArgs = maxTrailingArgs;
    }
    else
    {
      this.maxTrailingArgs = Integer.MAX_VALUE;
    }

    namedArgsByShortID    = new LinkedHashMap<Character,Argument>();
    namedArgsByLongID     = new LinkedHashMap<String,Argument>();
    namedArgs             = new ArrayList<Argument>();
    trailingArgs          = new ArrayList<String>();
    dependentArgumentSets = new ArrayList<ObjectPair<Argument,Set<Argument>>>();
    exclusiveArgumentSets = new ArrayList<Set<Argument>>();
    requiredArgumentSets  = new ArrayList<Set<Argument>>();
  }



  /**
   * Creates a new argument parser that is a "clean" copy of the provided source
   * argument parser.
   *
   * @param  source  The source argument parser to use for this argument parser.
   */
  private ArgumentParser(final ArgumentParser source)
  {
    commandName             = source.commandName;
    commandDescription      = source.commandDescription;
    maxTrailingArgs         = source.maxTrailingArgs;
    trailingArgsPlaceholder = source.trailingArgsPlaceholder;

    trailingArgs = new ArrayList<String>();

    namedArgs = new ArrayList<Argument>(source.namedArgs.size());
    namedArgsByLongID =
         new LinkedHashMap<String,Argument>(source.namedArgsByLongID.size());
    namedArgsByShortID = new LinkedHashMap<Character,Argument>(
         source.namedArgsByShortID.size());

    final LinkedHashMap<String,Argument> argsByID =
         new LinkedHashMap<String,Argument>(source.namedArgs.size());
    for (final Argument sourceArg : source.namedArgs)
    {
      final Argument a = sourceArg.getCleanCopy();

      try
      {
        a.setRegistered();
      }
      catch (final ArgumentException ae)
      {
        // This should never happen.
        Debug.debugException(ae);
      }

      namedArgs.add(a);
      argsByID.put(a.getIdentifierString(), a);

      for (final Character c : a.getShortIdentifiers())
      {
        namedArgsByShortID.put(c, a);
      }

      for (final String s : a.getLongIdentifiers())
      {
        namedArgsByLongID.put(toLowerCase(s), a);
      }
    }

    dependentArgumentSets = new ArrayList<ObjectPair<Argument,Set<Argument>>>(
         source.dependentArgumentSets.size());
    for (final ObjectPair<Argument,Set<Argument>> p :
         source.dependentArgumentSets)
    {
      final Set<Argument> sourceSet = p.getSecond();
      final LinkedHashSet<Argument> newSet =
           new LinkedHashSet<Argument>(sourceSet.size());
      for (final Argument a : sourceSet)
      {
        newSet.add(argsByID.get(a.getIdentifierString()));
      }

      final Argument sourceFirst = p.getFirst();
      final Argument newFirst = argsByID.get(sourceFirst.getIdentifierString());
      dependentArgumentSets.add(
           new ObjectPair<Argument, Set<Argument>>(newFirst, newSet));
    }

    exclusiveArgumentSets =
         new ArrayList<Set<Argument>>(source.exclusiveArgumentSets.size());
    for (final Set<Argument> sourceSet : source.exclusiveArgumentSets)
    {
      final LinkedHashSet<Argument> newSet =
           new LinkedHashSet<Argument>(sourceSet.size());
      for (final Argument a : sourceSet)
      {
        newSet.add(argsByID.get(a.getIdentifierString()));
      }

      exclusiveArgumentSets.add(newSet);
    }

    requiredArgumentSets =
         new ArrayList<Set<Argument>>(source.requiredArgumentSets.size());
    for (final Set<Argument> sourceSet : source.requiredArgumentSets)
    {
      final LinkedHashSet<Argument> newSet =
           new LinkedHashSet<Argument>(sourceSet.size());
      for (final Argument a : sourceSet)
      {
        newSet.add(argsByID.get(a.getIdentifierString()));
      }
      requiredArgumentSets.add(newSet);
    }
  }



  /**
   * Retrieves the name of the application or utility with which this command
   * line argument parser is associated.
   *
   * @return  The name of the application or utility with which this command
   *          line argument parser is associated.
   */
  public String getCommandName()
  {
    return commandName;
  }



  /**
   * Retrieves a description of the application or utility with which this
   * command line argument parser is associated.
   *
   * @return  A description of the application or utility with which this
   *          command line argument parser is associated.
   */
  public String getCommandDescription()
  {
    return commandDescription;
  }



  /**
   * Indicates whether this argument parser allows any unnamed trailing
   * arguments to be provided.
   *
   * @return  {@code true} if at least one unnamed trailing argument may be
   *          provided, or {@code false} if not.
   */
  public boolean allowsTrailingArguments()
  {
    return (maxTrailingArgs != 0);
  }



  /**
   * Retrieves the placeholder string that will be provided in usage information
   * to indicate what may be included in the trailing arguments.
   *
   * @return  The placeholder string that will be provided in usage information
   *          to indicate what may be included in the trailing arguments, or
   *          {@code null} if unnamed trailing arguments are not allowed.
   */
  public String getTrailingArgumentsPlaceholder()
  {
    return trailingArgsPlaceholder;
  }



  /**
   * Retrieves the maximum number of unnamed trailing arguments that may be
   * provided.
   *
   * @return  The maximum number of unnamed trailing arguments that may be
   *          provided.
   */
  public int getMaxTrailingArguments()
  {
    return maxTrailingArgs;
  }



  /**
   * Retrieves the named argument with the specified short identifier.
   *
   * @param  shortIdentifier  The short identifier of the argument to retrieve.
   *                          It must not be {@code null}.
   *
   * @return  The named argument with the specified short identifier, or
   *          {@code null} if there is no such argument.
   */
  public Argument getNamedArgument(final Character shortIdentifier)
  {
    ensureNotNull(shortIdentifier);
    return namedArgsByShortID.get(shortIdentifier);
  }



  /**
   * Retrieves the named argument with the specified long identifier.
   *
   * @param  longIdentifier  The long identifier of the argument to retrieve.
   *                         It must not be {@code null}.
   *
   * @return  The named argument with the specified long identifier, or
   *          {@code null} if there is no such argument.
   */
  public Argument getNamedArgument(final String longIdentifier)
  {
    ensureNotNull(longIdentifier);
    return namedArgsByLongID.get(toLowerCase(longIdentifier));
  }



  /**
   * Retrieves the set of named arguments defined for use with this argument
   * parser.
   *
   * @return  The set of named arguments defined for use with this argument
   *          parser.
   */
  public List<Argument> getNamedArguments()
  {
    return Collections.unmodifiableList(namedArgs);
  }



  /**
   * Registers the provided argument with this argument parser.
   *
   * @param  argument  The argument to be registered.
   *
   * @throws  ArgumentException  If the provided argument conflicts with another
   *                             argument already registered with this parser.
   */
  public void addArgument(final Argument argument)
         throws ArgumentException
  {
    argument.setRegistered();
    for (final Character c : argument.getShortIdentifiers())
    {
      if (namedArgsByShortID.containsKey(c))
      {
        throw new ArgumentException(ERR_PARSER_SHORT_ID_CONFLICT.get(c));
      }
    }

    for (final String s : argument.getLongIdentifiers())
    {
      if (namedArgsByLongID.containsKey(toLowerCase(s)))
      {
        throw new ArgumentException(ERR_PARSER_LONG_ID_CONFLICT.get(s));
      }
    }

    for (final Character c : argument.getShortIdentifiers())
    {
      namedArgsByShortID.put(c, argument);
    }

    for (final String s : argument.getLongIdentifiers())
    {
      namedArgsByLongID.put(toLowerCase(s), argument);
    }

    namedArgs.add(argument);
  }



  /**
   * Retrieves the list of dependent argument sets for this argument parser.  If
   * an argument contained as the first object in the pair in a dependent
   * argument set is provided, then at least one of the arguments in the paired
   * set must also be provided.
   *
   * @return  The list of dependent argument sets for this argument parser.
   */
  public List<ObjectPair<Argument,Set<Argument>>> getDependentArgumentSets()
  {
    return Collections.unmodifiableList(dependentArgumentSets);
  }



  /**
   * Adds the provided collection of arguments as dependent upon the given
   * argument.
   *
   * @param  targetArgument      The argument whose presence indicates that at
   *                             least one of the dependent arguments must also
   *                             be present.  It must not be {@code null}.
   * @param  dependentArguments  The set of arguments from which at least one
   *                             argument must be present if the target argument
   *                             is present.  It must not be {@code null} or
   *                             empty.
   */
  public void addDependentArgumentSet(final Argument targetArgument,
                   final Collection<Argument> dependentArguments)
  {
    ensureNotNull(targetArgument, dependentArguments);

    final LinkedHashSet<Argument> argSet =
         new LinkedHashSet<Argument>(dependentArguments);
    dependentArgumentSets.add(
         new ObjectPair<Argument,Set<Argument>>(targetArgument, argSet));
  }



  /**
   * Adds the provided collection of arguments as dependent upon the given
   * argument.
   *
   * @param  targetArgument  The argument whose presence indicates that at least
   *                         one of the dependent arguments must also be
   *                         present.  It must not be {@code null}.
   * @param  dependentArg1   The first argument in the set of arguments in which
   *                         at least one argument must be present if the target
   *                         argument is present.  It must not be {@code null}.
   * @param  remaining       The remaining arguments in the set of arguments in
   *                         which at least one argument must be present if the
   *                         target argument is present.
   */
  public void addDependentArgumentSet(final Argument targetArgument,
                                      final Argument dependentArg1,
                                      final Argument... remaining)
  {
    ensureNotNull(targetArgument, dependentArg1);

    final LinkedHashSet<Argument> argSet = new LinkedHashSet<Argument>();
    argSet.add(dependentArg1);
    argSet.addAll(Arrays.asList(remaining));

    dependentArgumentSets.add(
         new ObjectPair<Argument,Set<Argument>>(targetArgument, argSet));
  }



  /**
   * Retrieves the list of exclusive argument sets for this argument parser.
   * If an argument contained in an exclusive argument set is provided, then
   * none of the other arguments in that set may be provided.  It is acceptable
   * for none of the arguments in the set to be provided, unless the same set
   * of arguments is also defined as a required argument set.
   *
   * @return  The list of exclusive argument sets for this argument parser.
   */
  public List<Set<Argument>> getExclusiveArgumentSets()
  {
    return Collections.unmodifiableList(exclusiveArgumentSets);
  }



  /**
   * Adds the provided collection of arguments as an exclusive argument set, in
   * which at most one of the arguments may be provided.
   *
   * @param  exclusiveArguments  The collection of arguments to form an
   *                             exclusive argument set.  It must not be
   *                             {@code null}.
   */
  public void addExclusiveArgumentSet(
                   final Collection<Argument> exclusiveArguments)
  {
    ensureNotNull(exclusiveArguments);
    final LinkedHashSet<Argument> argSet =
         new LinkedHashSet<Argument>(exclusiveArguments);
    exclusiveArgumentSets.add(Collections.unmodifiableSet(argSet));
  }



  /**
   * Adds the provided set of arguments as an exclusive argument set, in
   * which at most one of the arguments may be provided.
   *
   * @param  arg1       The first argument to include in the exclusive argument
   *                    set.  It must not be {@code null}.
   * @param  arg2       The second argument to include in the exclusive argument
   *                    set.  It must not be {@code null}.
   * @param  remaining  Any additional arguments to include in the exclusive
   *                    argument set.
   */
  public void addExclusiveArgumentSet(final Argument arg1, final Argument arg2,
                                      final Argument... remaining)
  {
    ensureNotNull(arg1, arg2);

    final LinkedHashSet<Argument> argSet = new LinkedHashSet<Argument>();
    argSet.add(arg1);
    argSet.add(arg2);
    argSet.addAll(Arrays.asList(remaining));

    exclusiveArgumentSets.add(Collections.unmodifiableSet(argSet));
  }



  /**
   * Retrieves the list of required argument sets for this argument parser.  At
   * least one of the arguments contained in this set must be provided.  If this
   * same set is also defined as an exclusive argument set, then exactly one
   * of those arguments must be provided.
   *
   * @return  The list of required argument sets for this argument parser.
   */
  public List<Set<Argument>> getRequiredArgumentSets()
  {
    return Collections.unmodifiableList(requiredArgumentSets);
  }



  /**
   * Adds the provided collection of arguments as a required argument set, in
   * which at least one of the arguments must be provided.
   *
   * @param  requiredArguments  The collection of arguments to form an
   *                            required argument set.  It must not be
   *                            {@code null}.
   */
  public void addRequiredArgumentSet(
                   final Collection<Argument> requiredArguments)
  {
    ensureNotNull(requiredArguments);
    final LinkedHashSet<Argument> argSet =
         new LinkedHashSet<Argument>(requiredArguments);
    requiredArgumentSets.add(Collections.unmodifiableSet(argSet));
  }



  /**
   * Adds the provided set of arguments as a required argument set, in which
   * at least one of the arguments must be provided.
   *
   * @param  arg1       The first argument to include in the required argument
   *                    set.  It must not be {@code null}.
   * @param  arg2       The second argument to include in the required argument
   *                    set.  It must not be {@code null}.
   * @param  remaining  Any additional arguments to include in the required
   *                    argument set.
   */
  public void addRequiredArgumentSet(final Argument arg1, final Argument arg2,
                                     final Argument... remaining)
  {
    ensureNotNull(arg1, arg2);

    final LinkedHashSet<Argument> argSet = new LinkedHashSet<Argument>();
    argSet.add(arg1);
    argSet.add(arg2);
    argSet.addAll(Arrays.asList(remaining));

    requiredArgumentSets.add(Collections.unmodifiableSet(argSet));
  }



  /**
   * Retrieves the set of unnamed trailing arguments in the provided command
   * line arguments.
   *
   * @return  The set of unnamed trailing arguments in the provided command line
   *          arguments, or an empty list if there were none.
   */
  public List<String> getTrailingArguments()
  {
    return Collections.unmodifiableList(trailingArgs);
  }



  /**
   * Creates a copy of this argument parser that is "clean" and appears as if it
   * has not been used to parse an argument set.  The new parser will have all
   * of the same arguments and constraints as this parser.
   *
   * @return  The "clean" copy of this argument parser.
   */
  public ArgumentParser getCleanCopy()
  {
    return new ArgumentParser(this);
  }



  /**
   * Parses the provided set of arguments.
   *
   * @param  args  An array containing the argument information to parse.  It
   *               must not be {@code null}.
   *
   * @throws  ArgumentException  If a problem occurs while attempting to parse
   *                             the argument information.
   */
  public void parse(final String[] args)
         throws ArgumentException
  {
    // Iterate through the provided args strings and process them.
    boolean inTrailingArgs   = false;
    boolean usageArgProvided = false;
    for (int i=0; i < args.length; i++)
    {
      final String s = args[i];

      if (inTrailingArgs)
      {
        if (maxTrailingArgs == 0)
        {
          throw new ArgumentException(ERR_PARSER_TRAILING_ARGS_NOT_ALLOWED.get(
                                           s, commandName));
        }
        else if (trailingArgs.size() >= maxTrailingArgs)
        {
          throw new ArgumentException(ERR_PARSER_TOO_MANY_TRAILING_ARGS.get(s,
                                           commandName, maxTrailingArgs));
        }
        else
        {
          trailingArgs.add(s);
        }
      }
      else if (s.equals("--"))
      {
        // This signifies the end of the named arguments and the beginning of
        // the trailing arguments.
        inTrailingArgs = true;
      }
      else if (s.startsWith("--"))
      {
        // There may be an equal sign to separate the name from the value.
        final String argName;
        final int equalPos = s.indexOf('=');
        if (equalPos > 0)
        {
          argName = s.substring(2, equalPos);
        }
        else
        {
          argName = s.substring(2);
        }

        final Argument a = namedArgsByLongID.get(toLowerCase(argName));
        if (a == null)
        {
          throw new ArgumentException(ERR_PARSER_NO_SUCH_LONG_ID.get(argName));
        }
        else if(a.isUsageArgument())
        {
          usageArgProvided = true;
        }

        a.incrementOccurrences();
        if (a.takesValue())
        {
          if (equalPos > 0)
          {
            a.addValue(s.substring(equalPos+1));
          }
          else
          {
            i++;
            if (i >= args.length)
            {
              throw new ArgumentException(ERR_PARSER_LONG_ARG_MISSING_VALUE.get(
                                               argName));
            }
            else
            {
              a.addValue(args[i]);
            }
          }
        }
        else
        {
          if (equalPos > 0)
          {
            throw new ArgumentException(
                           ERR_PARSER_LONG_ARG_DOESNT_TAKE_VALUE.get(argName));
          }
        }
      }
      else if (s.startsWith("-"))
      {
        if (s.length() == 1)
        {
          throw new ArgumentException(ERR_PARSER_UNEXPECTED_DASH.get());
        }
        else if (s.length() == 2)
        {
          final char c = s.charAt(1);
          final Argument a = namedArgsByShortID.get(c);
          if (a == null)
          {
            throw new ArgumentException(ERR_PARSER_NO_SUCH_SHORT_ID.get(c));
          }
          else if(a.isUsageArgument())
          {
            usageArgProvided = true;
          }

          a.incrementOccurrences();
          if (a.takesValue())
          {
            i++;
            if (i >= args.length)
            {
              throw new ArgumentException(
                             ERR_PARSER_SHORT_ARG_MISSING_VALUE.get(c));
            }
            else
            {
              a.addValue(args[i]);
            }
          }
        }
        else
        {
          char c = s.charAt(1);
          Argument a = namedArgsByShortID.get(c);
          if (a == null)
          {
            throw new ArgumentException(ERR_PARSER_NO_SUCH_SHORT_ID.get(c));
          }
          else if(a.isUsageArgument())
          {
            usageArgProvided = true;
          }

          a.incrementOccurrences();
          if (a.takesValue())
          {
            a.addValue(s.substring(2));
          }
          else
          {
            // The rest of the characters in the string must also resolve to
            // arguments that don't take values.
            for (int j=2; j < s.length(); j++)
            {
              c = s.charAt(j);
              a = namedArgsByShortID.get(c);
              if (a == null)
              {
                throw new ArgumentException(
                               ERR_PARSER_NO_SUBSEQUENT_SHORT_ARG.get(c, s));
              }
              else if(a.isUsageArgument())
              {
                usageArgProvided = true;
              }

              a.incrementOccurrences();
              if (a.takesValue())
              {
                throw new ArgumentException(
                               ERR_PARSER_SUBSEQUENT_SHORT_ARG_TAKES_VALUE.get(
                                    c, s));
              }
            }
          }
        }
      }
      else
      {
        inTrailingArgs = true;
        if (maxTrailingArgs == 0)
        {
          throw new ArgumentException(ERR_PARSER_TRAILING_ARGS_NOT_ALLOWED.get(
                                           s, commandName));
        }
        else
        {
          trailingArgs.add(s);
        }
      }
    }


    // If a usage argument was provided, then no further validation should be
    // performed.
    if (usageArgProvided)
    {
      return;
    }


    // Make sure that all required arguments have values.
    for (final Argument a : namedArgs)
    {
      if (a.isRequired() && (! a.isPresent()))
      {
        throw new ArgumentException(ERR_PARSER_MISSING_REQUIRED_ARG.get(
                                         a.getIdentifierString()));
      }
    }


    // Make sure that there are no dependent argument set conflicts.
    for (final ObjectPair<Argument,Set<Argument>> p : dependentArgumentSets)
    {
      final Argument targetArg = p.getFirst();
      if (targetArg.isPresent())
      {
        final Set<Argument> argSet = p.getSecond();
        boolean found = false;
        for (final Argument a : argSet)
        {
          if (a.isPresent())
          {
            found = true;
            break;
          }
        }

        if (! found)
        {
          if (argSet.size() == 1)
          {
            throw new ArgumentException(
                 ERR_PARSER_DEPENDENT_CONFLICT_SINGLE.get(
                      targetArg.getIdentifierString(),
                      argSet.iterator().next().getIdentifierString()));
          }
          else
          {
            boolean first = true;
            final StringBuilder buffer = new StringBuilder();
            for (final Argument a : argSet)
            {
              if (first)
              {
                first = false;
              }
              else
              {
                buffer.append(", ");
              }
              buffer.append(a.getIdentifierString());
            }
            throw new ArgumentException(
                 ERR_PARSER_DEPENDENT_CONFLICT_MULTIPLE.get(
                      targetArg.getIdentifierString(), buffer.toString()));
          }
        }
      }
    }


    // Make sure that there are no exclusive argument set conflicts.
    for (final Set<Argument> argSet : exclusiveArgumentSets)
    {
      Argument setArg = null;
      for (final Argument a : argSet)
      {
        if (a.isPresent())
        {
          if (setArg == null)
          {
            setArg = a;
          }
          else
          {
            throw new ArgumentException(ERR_PARSER_EXCLUSIVE_CONFLICT.get(
                                             setArg.getIdentifierString(),
                                             a.getIdentifierString()));
          }
        }
      }
    }

    // Make sure that there are no required argument set conflicts.
    for (final Set<Argument> argSet : requiredArgumentSets)
    {
      boolean found = false;
      for (final Argument a : argSet)
      {
        if (a.isPresent())
        {
          found = true;
          break;
        }
      }

      if (! found)
      {
        boolean first = true;
        final StringBuilder buffer = new StringBuilder();
        for (final Argument a : argSet)
        {
          if (first)
          {
            first = false;
          }
          else
          {
            buffer.append(", ");
          }
          buffer.append(a.getIdentifierString());
        }
        throw new ArgumentException(ERR_PARSER_REQUIRED_CONFLICT.get(
                                         buffer.toString()));
      }
    }
  }



  /**
   * Retrieves lines that make up the usage information for this program,
   * optionally wrapping long lines.
   *
   * @param  maxWidth  The maximum line width to use for the output.  If this is
   *                   less than or equal to zero, then no wrapping will be
   *                   performed.
   *
   * @return  The lines that make up the usage information for this program.
   */
  public List<String> getUsage(final int maxWidth)
  {
    final ArrayList<String> lines = new ArrayList<String>(100);

    // First is a description of the command.
    lines.addAll(wrapLine(commandDescription, maxWidth));
    lines.add("");

    // Next comes the usage.  It may include neither, either, or both of the
    // set of options and trailing arguments.
    if (namedArgs.isEmpty())
    {
      if (maxTrailingArgs == 0)
      {
        lines.addAll(wrapLine(INFO_USAGE_NOOPTIONS_NOTRAILING.get(commandName),
                              maxWidth));
      }
      else
      {
        lines.addAll(wrapLine(INFO_USAGE_NOOPTIONS_TRAILING.get(
                                   commandName, trailingArgsPlaceholder),
                              maxWidth));
      }
    }
    else
    {
      if (maxTrailingArgs == 0)
      {
        lines.addAll(wrapLine(INFO_USAGE_OPTIONS_NOTRAILING.get(commandName),
                              maxWidth));
      }
      else
      {
        lines.addAll(wrapLine(INFO_USAGE_OPTIONS_TRAILING.get(
                                   commandName, trailingArgsPlaceholder),
                              maxWidth));
      }

      lines.add("");
      lines.add(INFO_USAGE_OPTIONS_INCLUDE.get());


      // We know that there are named arguments, so we'll want to display them
      // and their descriptions.
      for (final Argument a : namedArgs)
      {
        if (a.isHidden())
        {
          // This shouldn't be included in the usage output.
          continue;
        }

        final StringBuilder argLine = new StringBuilder();
        boolean first = true;
        for (final Character c : a.getShortIdentifiers())
        {
          if (first)
          {
            argLine.append('-');
            first = false;
          }
          else
          {
            argLine.append(", -");
          }
          argLine.append(c);
        }

        for (final String s : a.getLongIdentifiers())
        {
          if (first)
          {
            argLine.append("--");
          }
          else
          {
            argLine.append(", --");
          }
          argLine.append(s);
        }

        final String valuePlaceholder = a.getValuePlaceholder();
        if (valuePlaceholder != null)
        {
          argLine.append(' ');
          argLine.append(valuePlaceholder);
        }

        // NOTE:  This line won't be wrapped.  That's intentional because I
        // think it would probably look bad no matter how we did it.
        lines.add(argLine.toString());

        // The description should be wrapped, if necessary.  We'll also want to
        // indent it (unless someone chose an absurdly small wrap width) to make
        // it stand out from the argument lines.
        final String description = a.getDescription();
        if (maxWidth > 10)
        {
          final List<String> descLines = wrapLine(description, (maxWidth-4));
          for (final String s : descLines)
          {
            lines.add("    " + s);
          }
        }
        else
        {
          lines.addAll(wrapLine(description, maxWidth));
        }
      }
    }

    return lines;
  }



  /**
   * Writes usage information for this program to the provided output stream
   * using the UTF-8 encoding, optionally wrapping long lines.
   *
   * @param  outputStream  The output stream to which the usage information
   *                       should be written.  It must not be {@code null}.
   * @param  maxWidth      The maximum line width to use for the output.  If
   *                       this is less than or equal to zero, then no wrapping
   *                       will be performed.
   *
   * @throws  IOException  If an error occurs while attempting to write to the
   *                       provided output stream.
   */
  public void getUsage(final OutputStream outputStream, final int maxWidth)
         throws IOException
  {
    final List<String> usageLines = getUsage(maxWidth);
    for (final String s : usageLines)
    {
      outputStream.write(getBytes(s));
      outputStream.write(EOL_BYTES);
    }
  }



  /**
   * Retrieves a string representation of the usage information.
   *
   * @param  maxWidth  The maximum line width to use for the output.  If this is
   *                   less than or equal to zero, then no wrapping will be
   *                   performed.
   *
   * @return  A string representation of the usage information
   */
  public String getUsageString(final int maxWidth)
  {
    final StringBuilder buffer = new StringBuilder();
    getUsageString(buffer, maxWidth);
    return buffer.toString();
  }



  /**
   * Appends a string representation of the usage information to the provided
   * buffer.
   *
   * @param  buffer    The buffer to which the information should be appended.
   * @param  maxWidth  The maximum line width to use for the output.  If this is
   *                   less than or equal to zero, then no wrapping will be
   *                   performed.
   */
  public void getUsageString(final StringBuilder buffer, final int maxWidth)
  {
    for (final String line : getUsage(maxWidth))
    {
      buffer.append(line);
      buffer.append(EOL);
    }
  }



  /**
   * Retrieves a string representation of this argument parser.
   *
   * @return  A string representation of this argument parser.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this argument parser to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ArgumentParser(commandName='");
    buffer.append(commandName);
    buffer.append("', commandDescription='");
    buffer.append(commandDescription);
    buffer.append("', maxTrailingArgs=");
    buffer.append(maxTrailingArgs);

    if (trailingArgsPlaceholder != null)
    {
      buffer.append(", trailingArgsPlaceholder='");
      buffer.append(trailingArgsPlaceholder);
      buffer.append('\'');
    }

    buffer.append("namedArgs={");

    final Iterator<Argument> iterator = namedArgs.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
