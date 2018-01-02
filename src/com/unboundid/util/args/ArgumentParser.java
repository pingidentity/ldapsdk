/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
   * The name of the system property that can be used to specify the default
   * properties file that should be used to obtain the default values for
   * arguments not specified via the command line.
   */
  public static final String PROPERTY_DEFAULT_PROPERTIES_FILE_PATH =
       ArgumentParser.class.getName() + ".propertiesFilePath";



  /**
   * The name of an environment variable that can be used to specify the default
   * properties file that should be used to obtain the default values for
   * arguments not specified via the command line.
   */
  public static final String ENV_DEFAULT_PROPERTIES_FILE_PATH =
       "UNBOUNDID_TOOL_PROPERTIES_FILE_PATH";



  /**
   * The name of the argument used to specify the path to a file to which all
   * output should be written.
   */
  private static final String ARG_NAME_OUTPUT_FILE = "outputFile";



  /**
   * The name of the argument used to indicate that output should be written to
   * both the output file and the console.
   */
  private static final String ARG_NAME_TEE_OUTPUT = "teeOutput";



  /**
   * The name of the argument used to specify the path to a properties file from
   * which to obtain the default values for arguments not specified via the
   * command line.
   */
  private static final String ARG_NAME_PROPERTIES_FILE_PATH =
       "propertiesFilePath";



  /**
   * The name of the argument used to specify the path to a file to be generated
   * with information about the properties that the tool supports.
   */
  private static final String ARG_NAME_GENERATE_PROPERTIES_FILE =
       "generatePropertiesFile";



  /**
   * The name of the argument used to indicate that the tool should not use any
   * properties file to obtain default values for arguments not specified via
   * the command line.
   */
  private static final String ARG_NAME_NO_PROPERTIES_FILE = "noPropertiesFile";



  /**
   * The name of the argument used to indicate that the tool should suppress the
   * comment that lists the argument values obtained from a properties file.
   */
  private static final String ARG_NAME_SUPPRESS_PROPERTIES_FILE_COMMENT =
       "suppressPropertiesFileComment";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3053102992180360269L;



  // The properties file used to obtain arguments for this tool.
  private volatile File propertiesFileUsed;

  // The maximum number of trailing arguments allowed to be provided.
  private final int maxTrailingArgs;

  // The minimum number of trailing arguments allowed to be provided.
  private final int minTrailingArgs;

  // The set of named arguments associated with this parser, indexed by short
  // identifier.
  private final LinkedHashMap<Character,Argument> namedArgsByShortID;

  // The set of named arguments associated with this parser, indexed by long
  // identifier.
  private final LinkedHashMap<String,Argument> namedArgsByLongID;

  // The set of subcommands associated with this parser, indexed by name.
  private final LinkedHashMap<String,SubCommand> subCommandsByName;

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

  // A list of any arguments set from the properties file rather than explicitly
  // provided on the command line.
  private final List<String> argumentsSetFromPropertiesFile;

  // The list of trailing arguments provided on the command line.
  private final List<String> trailingArgs;

  // The full list of subcommands associated with this argument parser.
  private final List<SubCommand> subCommands;

  // The description for the associated command.
  private final String commandDescription;

  // The name for the associated command.
  private final String commandName;

  // The placeholder string for the trailing arguments.
  private final String trailingArgsPlaceholder;

  // The subcommand with which this argument parser is associated.
  private volatile SubCommand parentSubCommand;

  // The subcommand that was included in the set of command-line arguments.
  private volatile SubCommand selectedSubCommand;



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
    this(commandName, commandDescription, 0, maxTrailingArgs,
         trailingArgsPlaceholder);
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
   * @param  minTrailingArgs          The minimum number of trailing arguments
   *                                  that must be provided for this command.  A
   *                                  value of zero indicates that the command
   *                                  may be invoked without any trailing
   *                                  arguments.
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
                        final int minTrailingArgs,
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

    if (minTrailingArgs >= 0)
    {
      this.minTrailingArgs = minTrailingArgs;
    }
    else
    {
      this.minTrailingArgs = 0;
    }

    if (maxTrailingArgs >= 0)
    {
      this.maxTrailingArgs = maxTrailingArgs;
    }
    else
    {
      this.maxTrailingArgs = Integer.MAX_VALUE;
    }

    if (this.minTrailingArgs > this.maxTrailingArgs)
    {
      throw new ArgumentException(ERR_PARSER_TRAILING_ARGS_COUNT_MISMATCH.get(
           this.minTrailingArgs, this.maxTrailingArgs));
    }

    namedArgsByShortID    = new LinkedHashMap<Character,Argument>();
    namedArgsByLongID     = new LinkedHashMap<String,Argument>();
    namedArgs             = new ArrayList<Argument>();
    trailingArgs          = new ArrayList<String>();
    dependentArgumentSets = new ArrayList<ObjectPair<Argument,Set<Argument>>>();
    exclusiveArgumentSets = new ArrayList<Set<Argument>>();
    requiredArgumentSets  = new ArrayList<Set<Argument>>();
    parentSubCommand      = null;
    selectedSubCommand    = null;
    subCommands           = new ArrayList<SubCommand>();
    subCommandsByName     = new LinkedHashMap<String,SubCommand>(10);
    propertiesFileUsed    = null;
    argumentsSetFromPropertiesFile = new ArrayList<String>();
  }



  /**
   * Creates a new argument parser that is a "clean" copy of the provided source
   * argument parser.
   *
   * @param  source      The source argument parser to use for this argument
   *                     parser.
   * @param  subCommand  The subcommand with which this argument parser is to be
   *                     associated.
   */
  ArgumentParser(final ArgumentParser source, final SubCommand subCommand)
  {
    commandName             = source.commandName;
    commandDescription      = source.commandDescription;
    minTrailingArgs         = source.minTrailingArgs;
    maxTrailingArgs         = source.maxTrailingArgs;
    trailingArgsPlaceholder = source.trailingArgsPlaceholder;

    propertiesFileUsed = null;
    argumentsSetFromPropertiesFile = new ArrayList<String>();
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

      for (final Character c : a.getShortIdentifiers(true))
      {
        namedArgsByShortID.put(c, a);
      }

      for (final String s : a.getLongIdentifiers(true))
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

    parentSubCommand = subCommand;
    selectedSubCommand = null;
    subCommands = new ArrayList<SubCommand>(source.subCommands.size());
    subCommandsByName =
         new LinkedHashMap<String,SubCommand>(source.subCommandsByName.size());
    for (final SubCommand sc : source.subCommands)
    {
      subCommands.add(sc.getCleanCopy());
      for (final String name : sc.getNames(true))
      {
        subCommandsByName.put(toLowerCase(name), sc);
      }
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
   * Indicates whether this argument parser requires at least unnamed trailing
   * argument to be provided.
   *
   * @return  {@code true} if at least one unnamed trailing argument must be
   *          provided, or {@code false} if the tool may be invoked without any
   *          such arguments.
   */
  public boolean requiresTrailingArguments()
  {
    return (minTrailingArgs != 0);
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
   * Retrieves the minimum number of unnamed trailing arguments that must be
   * provided.
   *
   * @return  The minimum number of unnamed trailing arguments that must be
   *          provided.
   */
  public int getMinTrailingArguments()
  {
    return minTrailingArgs;
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
   * Updates this argument parser to enable support for a properties file that
   * can be used to specify the default values for any properties that were not
   * supplied via the command line.  This method should be invoked after the
   * argument parser has been configured with all of the other arguments that it
   * supports and before the {@link #parse} method is invoked.  In addition,
   * after invoking the {@code parse} method, the caller must also invoke the
   * {@link #getGeneratedPropertiesFile} method to determine if the only
   * processing performed that should be performed is the generation of a
   * properties file that will have already been performed.
   * <BR><BR>
   * This method will update the argument parser to add the following additional
   * arguments:
   * <UL>
   *   <LI>
   *     {@code propertiesFilePath} -- Specifies the path to the properties file
   *     that should be used to obtain default values for any arguments not
   *     provided on the command line.  If this is not specified and the
   *     {@code noPropertiesFile} argument is not present, then the argument
   *     parser may use a default properties file path specified using either
   *     the {@code com.unboundid.util.args.ArgumentParser..propertiesFilePath}
   *     system property or the {@code UNBOUNDID_TOOL_PROPERTIES_FILE_PATH}
   *     environment variable.
   *   </LI>
   *   <LI>
   *     {@code generatePropertiesFile} -- Indicates that the tool should
   *     generate a properties file for this argument parser and write it to the
   *     specified location.  The generated properties file will not have any
   *     properties set, but will include comments that describe all of the
   *     supported arguments, as well general information about the use of a
   *     properties file.  If this argument is specified on the command line,
   *     then no other arguments should be given.
   *   </LI>
   *   <LI>
   *     {@code noPropertiesFile} -- Indicates that the tool should not use a
   *     properties file to obtain default values for any arguments not provided
   *     on the command line.
   *   </LI>
   * </UL>
   *
   * @throws  ArgumentException  If any of the arguments related to properties
   *                             file processing conflicts with an argument that
   *                             has already been added to the argument parser.
   */
  public void enablePropertiesFileSupport()
         throws ArgumentException
  {
    final FileArgument propertiesFilePath = new FileArgument(null,
         ARG_NAME_PROPERTIES_FILE_PATH, false, 1, null,
         INFO_ARG_DESCRIPTION_PROP_FILE_PATH.get(), true, true, true, false);
    propertiesFilePath.setUsageArgument(true);
    propertiesFilePath.addLongIdentifier("properties-file-path", true);
    addArgument(propertiesFilePath);

    final FileArgument generatePropertiesFile = new FileArgument(null,
         ARG_NAME_GENERATE_PROPERTIES_FILE, false, 1, null,
         INFO_ARG_DESCRIPTION_GEN_PROP_FILE.get(), false, true, true, false);
    generatePropertiesFile.setUsageArgument(true);
    generatePropertiesFile.addLongIdentifier("generate-properties-file", true);
    addArgument(generatePropertiesFile);

    final BooleanArgument noPropertiesFile = new BooleanArgument(null,
         ARG_NAME_NO_PROPERTIES_FILE, INFO_ARG_DESCRIPTION_NO_PROP_FILE.get());
    noPropertiesFile.setUsageArgument(true);
    noPropertiesFile.addLongIdentifier("no-properties-file", true);
    addArgument(noPropertiesFile);

    final BooleanArgument suppressPropertiesFileComment = new BooleanArgument(
         null, ARG_NAME_SUPPRESS_PROPERTIES_FILE_COMMENT, 1,
         INFO_ARG_DESCRIPTION_SUPPRESS_PROP_FILE_COMMENT.get());
    suppressPropertiesFileComment.setUsageArgument(true);
    suppressPropertiesFileComment.addLongIdentifier(
         "suppress-properties-file-comment", true);
    addArgument(suppressPropertiesFileComment);


    // The propertiesFilePath and noPropertiesFile arguments cannot be used
    // together.
    addExclusiveArgumentSet(propertiesFilePath, noPropertiesFile);
  }



  /**
   * Indicates whether this argument parser was used to generate a properties
   * file.  If so, then the tool invoking the parser should return without
   * performing any further processing.
   *
   * @return  A {@code File} object that represents the path to the properties
   *          file that was generated, or {@code null} if no properties file was
   *          generated.
   */
  public File getGeneratedPropertiesFile()
  {
    final Argument a = getNamedArgument(ARG_NAME_GENERATE_PROPERTIES_FILE);
    if ((a == null) || (! a.isPresent()) || (! (a instanceof FileArgument)))
    {
      return null;
    }

    return ((FileArgument) a).getValue();
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
   * Retrieves the named argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The named argument with the specified long identifier, or
   *          {@code null} if there is no such argument.
   */
  public Argument getNamedArgument(final String identifier)
  {
    ensureNotNull(identifier);

    if (identifier.startsWith("--") && (identifier.length() > 2))
    {
      return namedArgsByLongID.get(toLowerCase(identifier.substring(2)));
    }
    else if (identifier.startsWith("-") && (identifier.length() == 2))
    {
      return namedArgsByShortID.get(identifier.charAt(1));
    }
    else
    {
      return namedArgsByLongID.get(toLowerCase(identifier));
    }
  }



  /**
   * Retrieves the argument list argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The argument list argument with the specified identifier, or
   *          {@code null} if there is no such argument.
   */
  public ArgumentListArgument getArgumentListArgument(final String identifier)
  {
    final Argument a = getNamedArgument(identifier);
    if (a == null)
    {
      return null;
    }
    else
    {
      return (ArgumentListArgument) a;
    }
  }



  /**
   * Retrieves the Boolean argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The Boolean argument with the specified identifier, or
   *          {@code null} if there is no such argument.
   */
  public BooleanArgument getBooleanArgument(final String identifier)
  {
    final Argument a = getNamedArgument(identifier);
    if (a == null)
    {
      return null;
    }
    else
    {
      return (BooleanArgument) a;
    }
  }



  /**
   * Retrieves the Boolean value argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The Boolean value argument with the specified identifier, or
   *          {@code null} if there is no such argument.
   */
  public BooleanValueArgument getBooleanValueArgument(final String identifier)
  {
    final Argument a = getNamedArgument(identifier);
    if (a == null)
    {
      return null;
    }
    else
    {
      return (BooleanValueArgument) a;
    }
  }



  /**
   * Retrieves the control argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The control argument with the specified identifier, or
   *          {@code null} if there is no such argument.
   */
  public ControlArgument getControlArgument(final String identifier)
  {
    final Argument a = getNamedArgument(identifier);
    if (a == null)
    {
      return null;
    }
    else
    {
      return (ControlArgument) a;
    }
  }



  /**
   * Retrieves the DN argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The DN argument with the specified identifier, or
   *          {@code null} if there is no such argument.
   */
  public DNArgument getDNArgument(final String identifier)
  {
    final Argument a = getNamedArgument(identifier);
    if (a == null)
    {
      return null;
    }
    else
    {
      return (DNArgument) a;
    }
  }



  /**
   * Retrieves the duration argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The duration argument with the specified identifier, or
   *          {@code null} if there is no such argument.
   */
  public DurationArgument getDurationArgument(final String identifier)
  {
    final Argument a = getNamedArgument(identifier);
    if (a == null)
    {
      return null;
    }
    else
    {
      return (DurationArgument) a;
    }
  }



  /**
   * Retrieves the file argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The file argument with the specified identifier, or
   *          {@code null} if there is no such argument.
   */
  public FileArgument getFileArgument(final String identifier)
  {
    final Argument a = getNamedArgument(identifier);
    if (a == null)
    {
      return null;
    }
    else
    {
      return (FileArgument) a;
    }
  }



  /**
   * Retrieves the filter argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The filter argument with the specified identifier, or
   *          {@code null} if there is no such argument.
   */
  public FilterArgument getFilterArgument(final String identifier)
  {
    final Argument a = getNamedArgument(identifier);
    if (a == null)
    {
      return null;
    }
    else
    {
      return (FilterArgument) a;
    }
  }



  /**
   * Retrieves the integer argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The integer argument with the specified identifier, or
   *          {@code null} if there is no such argument.
   */
  public IntegerArgument getIntegerArgument(final String identifier)
  {
    final Argument a = getNamedArgument(identifier);
    if (a == null)
    {
      return null;
    }
    else
    {
      return (IntegerArgument) a;
    }
  }



  /**
   * Retrieves the scope argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The scope argument with the specified identifier, or
   *          {@code null} if there is no such argument.
   */
  public ScopeArgument getScopeArgument(final String identifier)
  {
    final Argument a = getNamedArgument(identifier);
    if (a == null)
    {
      return null;
    }
    else
    {
      return (ScopeArgument) a;
    }
  }



  /**
   * Retrieves the string argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The string argument with the specified identifier, or
   *          {@code null} if there is no such argument.
   */
  public StringArgument getStringArgument(final String identifier)
  {
    final Argument a = getNamedArgument(identifier);
    if (a == null)
    {
      return null;
    }
    else
    {
      return (StringArgument) a;
    }
  }



  /**
   * Retrieves the timestamp argument with the specified identifier.
   *
   * @param  identifier  The identifier of the argument to retrieve.  It may be
   *                     the long identifier without any dashes, the short
   *                     identifier character preceded by a single dash, or the
   *                     long identifier preceded by two dashes. It must not be
   *                     {@code null}.
   *
   * @return  The timestamp argument with the specified identifier, or
   *          {@code null} if there is no such argument.
   */
  public TimestampArgument getTimestampArgument(final String identifier)
  {
    final Argument a = getNamedArgument(identifier);
    if (a == null)
    {
      return null;
    }
    else
    {
      return (TimestampArgument) a;
    }
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
    for (final Character c : argument.getShortIdentifiers(true))
    {
      if (namedArgsByShortID.containsKey(c))
      {
        throw new ArgumentException(ERR_PARSER_SHORT_ID_CONFLICT.get(c));
      }

      if ((parentSubCommand != null) &&
          (parentSubCommand.getArgumentParser().namedArgsByShortID.containsKey(
               c)))
      {
        throw new ArgumentException(ERR_PARSER_SHORT_ID_CONFLICT.get(c));
      }
    }

    for (final String s : argument.getLongIdentifiers(true))
    {
      if (namedArgsByLongID.containsKey(toLowerCase(s)))
      {
        throw new ArgumentException(ERR_PARSER_LONG_ID_CONFLICT.get(s));
      }

      if ((parentSubCommand != null) &&
          (parentSubCommand.getArgumentParser().namedArgsByLongID.containsKey(
                toLowerCase(s))))
      {
        throw new ArgumentException(ERR_PARSER_LONG_ID_CONFLICT.get(s));
      }
    }

    for (final SubCommand sc : subCommands)
    {
      final ArgumentParser parser = sc.getArgumentParser();
      for (final Character c : argument.getShortIdentifiers(true))
      {
        if (parser.namedArgsByShortID.containsKey(c))
        {
          throw new ArgumentException(
               ERR_PARSER_SHORT_ID_CONFLICT_WITH_SUBCOMMAND.get(c,
                    sc.getPrimaryName()));
        }
      }

      for (final String s : argument.getLongIdentifiers(true))
      {
        if (parser.namedArgsByLongID.containsKey(toLowerCase(s)))
        {
          throw new ArgumentException(
               ERR_PARSER_LONG_ID_CONFLICT_WITH_SUBCOMMAND.get(s,
                    sc.getPrimaryName()));
        }
      }
    }

    for (final Character c : argument.getShortIdentifiers(true))
    {
      namedArgsByShortID.put(c, argument);
    }

    for (final String s : argument.getLongIdentifiers(true))
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
   * argument.  All of the arguments must have already been registered with this
   * argument parser using the {@link #addArgument} method.
   *
   * @param  targetArgument      The argument whose presence indicates that at
   *                             least one of the dependent arguments must also
   *                             be present.  It must not be {@code null}, and
   *                             it must have already been registered with this
   *                             argument parser.
   * @param  dependentArguments  The set of arguments from which at least one
   *                             argument must be present if the target argument
   *                             is present.  It must not be {@code null} or
   *                             empty, and all arguments must have already been
   *                             registered with this argument parser.
   */
  public void addDependentArgumentSet(final Argument targetArgument,
                   final Collection<Argument> dependentArguments)
  {
    ensureNotNull(targetArgument, dependentArguments);

    ensureFalse(dependentArguments.isEmpty(),
         "The ArgumentParser.addDependentArgumentSet method must not be " +
              "called with an empty collection of dependentArguments");

    ensureTrue(namedArgs.contains(targetArgument),
         "The ArgumentParser.addDependentArgumentSet method may only be used " +
              "if all of the provided arguments have already been registered " +
              "with the argument parser via the ArgumentParser.addArgument " +
              "method.  The " + targetArgument.getIdentifierString() +
              " argument has not been registered with the argument parser.");
    for (final Argument a : dependentArguments)
    {
      ensureTrue(namedArgs.contains(a),
           "The ArgumentParser.addDependentArgumentSet method may only be " +
                "used if all of the provided arguments have already been " +
                "registered with the argument parser via the " +
                "ArgumentParser.addArgument method.  The " +
                a.getIdentifierString() + " argument has not been registered " +
                "with the argument parser.");
    }

    final LinkedHashSet<Argument> argSet =
         new LinkedHashSet<Argument>(dependentArguments);
    dependentArgumentSets.add(
         new ObjectPair<Argument,Set<Argument>>(targetArgument, argSet));
  }



  /**
   * Adds the provided collection of arguments as dependent upon the given
   * argument.  All of the arguments must have already been registered with this
   * argument parser using the {@link #addArgument} method.
   *
   * @param  targetArgument  The argument whose presence indicates that at least
   *                         one of the dependent arguments must also be
   *                         present.  It must not be {@code null}, and it must
   *                         have already been registered with this argument
   *                         parser.
   * @param  dependentArg1   The first argument in the set of arguments in which
   *                         at least one argument must be present if the target
   *                         argument is present.  It must not be {@code null},
   *                         and it must have already been registered with this
   *                         argument parser.
   * @param  remaining       The remaining arguments in the set of arguments in
   *                         which at least one argument must be present if the
   *                         target argument is present.  It may be {@code null}
   *                         or empty if no additional dependent arguments are
   *                         needed, but if it is non-empty then all arguments
   *                         must have already been registered with this
   *                         argument parser.
   */
  public void addDependentArgumentSet(final Argument targetArgument,
                                      final Argument dependentArg1,
                                      final Argument... remaining)
  {
    ensureNotNull(targetArgument, dependentArg1);

    ensureTrue(namedArgs.contains(targetArgument),
         "The ArgumentParser.addDependentArgumentSet method may only be used " +
              "if all of the provided arguments have already been registered " +
              "with the argument parser via the ArgumentParser.addArgument " +
              "method.  The " + targetArgument.getIdentifierString() +
              " argument has not been registered with the argument parser.");
    ensureTrue(namedArgs.contains(dependentArg1),
         "The ArgumentParser.addDependentArgumentSet method may only be used " +
              "if all of the provided arguments have already been registered " +
              "with the argument parser via the ArgumentParser.addArgument " +
              "method.  The " + dependentArg1.getIdentifierString() +
              " argument has not been registered with the argument parser.");
    if (remaining != null)
    {
      for (final Argument a : remaining)
      {
        ensureTrue(namedArgs.contains(a),
             "The ArgumentParser.addDependentArgumentSet method may only be " +
                  "used if all of the provided arguments have already been " +
                  "registered with the argument parser via the " +
                  "ArgumentParser.addArgument method.  The " +
                  a.getIdentifierString() + " argument has not been " +
                  "registered with the argument parser.");
      }
    }

    final LinkedHashSet<Argument> argSet = new LinkedHashSet<Argument>();
    argSet.add(dependentArg1);
    if (remaining != null)
    {
      argSet.addAll(Arrays.asList(remaining));
    }

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
   * which at most one of the arguments may be provided.  All of the arguments
   * must have already been registered with this argument parser using the
   * {@link #addArgument} method.
   *
   * @param  exclusiveArguments  The collection of arguments to form an
   *                             exclusive argument set.  It must not be
   *                             {@code null}, and all of the arguments must
   *                             have already been registered with this argument
   *                             parser.
   */
  public void addExclusiveArgumentSet(
                   final Collection<Argument> exclusiveArguments)
  {
    ensureNotNull(exclusiveArguments);

    for (final Argument a : exclusiveArguments)
    {
      ensureTrue(namedArgs.contains(a),
           "The ArgumentParser.addExclusiveArgumentSet method may only be " +
                "used if all of the provided arguments have already been " +
                "registered with the argument parser via the " +
                "ArgumentParser.addArgument method.  The " +
                a.getIdentifierString() + " argument has not been " +
                "registered with the argument parser.");
    }

    final LinkedHashSet<Argument> argSet =
         new LinkedHashSet<Argument>(exclusiveArguments);
    exclusiveArgumentSets.add(Collections.unmodifiableSet(argSet));
  }



  /**
   * Adds the provided set of arguments as an exclusive argument set, in
   * which at most one of the arguments may be provided.  All of the arguments
   * must have already been registered with this argument parser using the
   * {@link #addArgument} method.
   *
   * @param  arg1       The first argument to include in the exclusive argument
   *                    set.  It must not be {@code null}, and it must have
   *                    already been registered with this argument parser.
   * @param  arg2       The second argument to include in the exclusive argument
   *                    set.  It must not be {@code null}, and it must have
   *                    already been registered with this argument parser.
   * @param  remaining  Any additional arguments to include in the exclusive
   *                    argument set.  It may be {@code null} or empty if no
   *                    additional exclusive arguments are needed, but if it is
   *                    non-empty then all arguments must have already been
   *                    registered with this argument parser.
   */
  public void addExclusiveArgumentSet(final Argument arg1, final Argument arg2,
                                      final Argument... remaining)
  {
    ensureNotNull(arg1, arg2);

    ensureTrue(namedArgs.contains(arg1),
         "The ArgumentParser.addExclusiveArgumentSet method may only be " +
              "used if all of the provided arguments have already been " +
              "registered with the argument parser via the " +
              "ArgumentParser.addArgument method.  The " +
              arg1.getIdentifierString() + " argument has not been " +
              "registered with the argument parser.");
    ensureTrue(namedArgs.contains(arg2),
         "The ArgumentParser.addExclusiveArgumentSet method may only be " +
              "used if all of the provided arguments have already been " +
              "registered with the argument parser via the " +
              "ArgumentParser.addArgument method.  The " +
              arg2.getIdentifierString() + " argument has not been " +
              "registered with the argument parser.");

    if (remaining != null)
    {
      for (final Argument a : remaining)
      {
        ensureTrue(namedArgs.contains(a),
             "The ArgumentParser.addExclusiveArgumentSet method may only be " +
                  "used if all of the provided arguments have already been " +
                  "registered with the argument parser via the " +
                  "ArgumentParser.addArgument method.  The " +
                  a.getIdentifierString() + " argument has not been " +
                  "registered with the argument parser.");
      }
    }

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
   * which at least one of the arguments must be provided.  All of the arguments
   * must have already been registered with this argument parser using the
   * {@link #addArgument} method.
   *
   * @param  requiredArguments  The collection of arguments to form an
   *                            required argument set.  It must not be
   *                            {@code null}, and all of the arguments must have
   *                            already been registered with this argument
   *                            parser.
   */
  public void addRequiredArgumentSet(
                   final Collection<Argument> requiredArguments)
  {
    ensureNotNull(requiredArguments);

    for (final Argument a : requiredArguments)
    {
      ensureTrue(namedArgs.contains(a),
           "The ArgumentParser.addRequiredArgumentSet method may only be " +
                "used if all of the provided arguments have already been " +
                "registered with the argument parser via the " +
                "ArgumentParser.addArgument method.  The " +
                a.getIdentifierString() + " argument has not been " +
                "registered with the argument parser.");
    }

    final LinkedHashSet<Argument> argSet =
         new LinkedHashSet<Argument>(requiredArguments);
    requiredArgumentSets.add(Collections.unmodifiableSet(argSet));
  }



  /**
   * Adds the provided set of arguments as a required argument set, in which
   * at least one of the arguments must be provided.  All of the arguments must
   * have already been registered with this argument parser using the
   * {@link #addArgument} method.
   *
   * @param  arg1       The first argument to include in the required argument
   *                    set.  It must not be {@code null}, and it must have
   *                    already been registered with this argument parser.
   * @param  arg2       The second argument to include in the required argument
   *                    set.  It must not be {@code null}, and it must have
   *                    already been registered with this argument parser.
   * @param  remaining  Any additional arguments to include in the required
   *                    argument set.  It may be {@code null} or empty if no
   *                    additional required arguments are needed, but if it is
   *                    non-empty then all arguments must have already been
   *                    registered with this argument parser.
   */
  public void addRequiredArgumentSet(final Argument arg1, final Argument arg2,
                                     final Argument... remaining)
  {
    ensureNotNull(arg1, arg2);

    ensureTrue(namedArgs.contains(arg1),
         "The ArgumentParser.addRequiredArgumentSet method may only be " +
              "used if all of the provided arguments have already been " +
              "registered with the argument parser via the " +
              "ArgumentParser.addArgument method.  The " +
              arg1.getIdentifierString() + " argument has not been " +
              "registered with the argument parser.");
    ensureTrue(namedArgs.contains(arg2),
         "The ArgumentParser.addRequiredArgumentSet method may only be " +
              "used if all of the provided arguments have already been " +
              "registered with the argument parser via the " +
              "ArgumentParser.addArgument method.  The " +
              arg2.getIdentifierString() + " argument has not been " +
              "registered with the argument parser.");

    if (remaining != null)
    {
      for (final Argument a : remaining)
      {
        ensureTrue(namedArgs.contains(a),
             "The ArgumentParser.addRequiredArgumentSet method may only be " +
                  "used if all of the provided arguments have already been " +
                  "registered with the argument parser via the " +
                  "ArgumentParser.addArgument method.  The " +
                  a.getIdentifierString() + " argument has not been " +
                  "registered with the argument parser.");
      }
    }

    final LinkedHashSet<Argument> argSet = new LinkedHashSet<Argument>();
    argSet.add(arg1);
    argSet.add(arg2);
    argSet.addAll(Arrays.asList(remaining));

    requiredArgumentSets.add(Collections.unmodifiableSet(argSet));
  }



  /**
   * Indicates whether any subcommands have been registered with this argument
   * parser.
   *
   * @return  {@code true} if one or more subcommands have been registered with
   *          this argument parser, or {@code false} if not.
   */
  public boolean hasSubCommands()
  {
    return (! subCommands.isEmpty());
  }



  /**
   * Retrieves the subcommand that was provided in the set of command-line
   * arguments, if any.
   *
   * @return  The subcommand that was provided in the set of command-line
   *          arguments, or {@code null} if there is none.
   */
  public SubCommand getSelectedSubCommand()
  {
    return selectedSubCommand;
  }



  /**
   * Specifies the subcommand that was provided in the set of command-line
   * arguments.
   *
   * @param  subcommand  The subcommand that was provided in the set of
   *                     command-line arguments.  It may be {@code null} if no
   *                     subcommand should be used.
   */
  void setSelectedSubCommand(final SubCommand subcommand)
  {
    selectedSubCommand = subcommand;
    if (subcommand != null)
    {
      subcommand.setPresent();
    }
  }



  /**
   * Retrieves a list of all subcommands associated with this argument parser.
   *
   * @return  A list of all subcommands associated with this argument parser, or
   *          an empty list if there are no associated subcommands.
   */
  public List<SubCommand> getSubCommands()
  {
    return Collections.unmodifiableList(subCommands);
  }



  /**
   * Retrieves the subcommand for the provided name.
   *
   * @param  name  The name of the subcommand to retrieve.
   *
   * @return  The subcommand with the provided name, or {@code null} if there is
   *          no such subcommand.
   */
  public SubCommand getSubCommand(final String name)
  {
    if (name == null)
    {
      return null;
    }

    return subCommandsByName.get(toLowerCase(name));
  }



  /**
   * Registers the provided subcommand with this argument parser.
   *
   * @param  subCommand  The subcommand to register with this argument parser.
   *                     It must not be {@code null}.
   *
   * @throws  ArgumentException  If this argument parser does not allow
   *                             subcommands, if there is a conflict between any
   *                             of the names of the provided subcommand and an
   *                             already-registered subcommand, or if there is a
   *                             conflict between any of the subcommand-specific
   *                             arguments and global arguments.
   */
  public void addSubCommand(final SubCommand subCommand)
         throws ArgumentException
  {
    // Ensure that the subcommand isn't already registered with an argument
    // parser.
    if (subCommand.getGlobalArgumentParser() != null)
    {
      throw new ArgumentException(
           ERR_PARSER_SUBCOMMAND_ALREADY_REGISTERED_WITH_PARSER.get());
    }

    // Ensure that the caller isn't trying to create a nested subcommand.
    if (this.parentSubCommand != null)
    {
      throw new ArgumentException(
           ERR_PARSER_CANNOT_CREATE_NESTED_SUBCOMMAND.get(
                this.parentSubCommand.getPrimaryName()));
    }

    // Ensure that this argument parser doesn't allow trailing arguments.
    if (allowsTrailingArguments())
    {
      throw new ArgumentException(
           ERR_PARSER_WITH_TRAILING_ARGS_CANNOT_HAVE_SUBCOMMANDS.get());
    }

    // Ensure that the subcommand doesn't have any names that conflict with an
    // existing subcommand.
    for (final String name : subCommand.getNames(true))
    {
      if (subCommandsByName.containsKey(toLowerCase(name)))
      {
        throw new ArgumentException(
             ERR_SUBCOMMAND_NAME_ALREADY_IN_USE.get(name));
      }
    }

    // Register the subcommand.
    for (final String name : subCommand.getNames(true))
    {
      subCommandsByName.put(toLowerCase(name), subCommand);
    }
    subCommands.add(subCommand);
    subCommand.setGlobalArgumentParser(this);
  }



  /**
   * Registers the provided additional name for this subcommand.
   *
   * @param  name        The name to be registered.  It must not be
   *                     {@code null} or empty.
   * @param  subCommand  The subcommand with which the name is associated.  It
   *                     must not be {@code null}.
   *
   * @throws  ArgumentException  If the provided name is already in use.
   */
  void addSubCommand(final String name, final SubCommand subCommand)
       throws ArgumentException
  {
    final String lowerName = toLowerCase(name);
    if (subCommandsByName.containsKey(lowerName))
    {
      throw new ArgumentException(
           ERR_SUBCOMMAND_NAME_ALREADY_IN_USE.get(name));
    }

    subCommandsByName.put(lowerName, subCommand);
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
   * Clears the set of trailing arguments for this argument parser.
   */
  void resetTrailingArguments()
  {
    trailingArgs.clear();
  }



  /**
   * Adds the provided value to the set of trailing arguments.
   *
   * @param  value  The value to add to the set of trailing arguments.
   *
   * @throws  ArgumentException  If the parser already has the maximum allowed
   *                             number of trailing arguments.
   */
  void addTrailingArgument(final String value)
       throws ArgumentException
  {
    if ((maxTrailingArgs > 0) && (trailingArgs.size() >= maxTrailingArgs))
    {
      throw new ArgumentException(ERR_PARSER_TOO_MANY_TRAILING_ARGS.get(value,
           commandName, maxTrailingArgs));
    }

    trailingArgs.add(value);
  }



  /**
   * Retrieves the properties file that was used to obtain values for arguments
   * not set on the command line.
   *
   * @return  The properties file that was used to obtain values for arguments
   *          not set on the command line, or {@code null} if no properties file
   *          was used.
   */
  public File getPropertiesFileUsed()
  {
    return propertiesFileUsed;
  }



  /**
   * Retrieves a list of the string representations of any arguments used for
   * the associated tool that were set from a properties file rather than
   * provided on the command line.  The values of any arguments marked as
   * sensitive will be obscured.
   *
   * @return  A list of the string representations any arguments used for the
   *          associated tool that were set from a properties file rather than
   *          provided on the command line, or an empty list if no arguments
   *          were set from a properties file.
   */
  public List<String> getArgumentsSetFromPropertiesFile()
  {
    return Collections.unmodifiableList(argumentsSetFromPropertiesFile);
  }



  /**
   * Indicates whether the comment listing arguments obtained from a properties
   * file should be suppressed.
   *
   * @return  {@code true} if the comment listing arguments obtained from a
   *          properties file should be suppressed, or {@code false} if not.
   */
  public boolean suppressPropertiesFileComment()
  {
    final BooleanArgument arg =
         getBooleanArgument(ARG_NAME_SUPPRESS_PROPERTIES_FILE_COMMENT);
    return ((arg != null) && arg.isPresent());
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
    return new ArgumentParser(this, null);
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
    ArgumentParser subCommandParser    = null;
    boolean        inTrailingArgs      = false;
    boolean        skipFinalValidation = false;
    String         subCommandName      = null;
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

        final String lowerName = toLowerCase(argName);
        Argument a = namedArgsByLongID.get(lowerName);
        if ((a == null) && (subCommandParser != null))
        {
          a = subCommandParser.namedArgsByLongID.get(lowerName);
        }

        if (a == null)
        {
          throw new ArgumentException(ERR_PARSER_NO_SUCH_LONG_ID.get(argName));
        }
        else if (a.isUsageArgument())
        {
          skipFinalValidation |= skipFinalValidationBecauseOfArgument(a);
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

          Argument a = namedArgsByShortID.get(c);
          if ((a == null) && (subCommandParser != null))
          {
            a = subCommandParser.namedArgsByShortID.get(c);
          }

          if (a == null)
          {
            throw new ArgumentException(ERR_PARSER_NO_SUCH_SHORT_ID.get(c));
          }
          else if (a.isUsageArgument())
          {
            skipFinalValidation |= skipFinalValidationBecauseOfArgument(a);
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
          if ((a == null) && (subCommandParser != null))
          {
            a = subCommandParser.namedArgsByShortID.get(c);
          }

          if (a == null)
          {
            throw new ArgumentException(ERR_PARSER_NO_SUCH_SHORT_ID.get(c));
          }
          else if (a.isUsageArgument())
          {
            skipFinalValidation |= skipFinalValidationBecauseOfArgument(a);
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
              if ((a == null) && (subCommandParser != null))
              {
                a = subCommandParser.namedArgsByShortID.get(c);
              }

              if (a == null)
              {
                throw new ArgumentException(
                               ERR_PARSER_NO_SUBSEQUENT_SHORT_ARG.get(c, s));
              }
              else if (a.isUsageArgument())
              {
                skipFinalValidation |= skipFinalValidationBecauseOfArgument(a);
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
      else if (subCommands.isEmpty())
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
      else
      {
        if (selectedSubCommand == null)
        {
          subCommandName = s;
          selectedSubCommand = subCommandsByName.get(toLowerCase(s));
          if (selectedSubCommand == null)
          {
            throw new ArgumentException(ERR_PARSER_NO_SUCH_SUBCOMMAND.get(s,
                 commandName));
          }
          else
          {
            selectedSubCommand.setPresent();
            subCommandParser = selectedSubCommand.getArgumentParser();
          }
        }
        else
        {
          throw new ArgumentException(ERR_PARSER_CONFLICTING_SUBCOMMANDS.get(
               subCommandName, s));
        }
      }
    }


    // Perform any appropriate processing related to the use of a properties
    // file.
    if (! handlePropertiesFile())
    {
      return;
    }


    // If a usage argument was provided, then no further validation should be
    // performed.
    if (skipFinalValidation)
    {
      return;
    }


    // If any subcommands are defined, then one must have been provided.
    if ((! subCommands.isEmpty()) && (selectedSubCommand == null))
    {
      throw new ArgumentException(
           ERR_PARSER_MISSING_SUBCOMMAND.get(commandName));
    }


    doFinalValidation(this);
    if (selectedSubCommand != null)
    {
      doFinalValidation(selectedSubCommand.getArgumentParser());
    }
  }



  /**
   * Performs the final validation for the provided argument parser.
   *
   * @param  parser  The argument parser for which to perform the final
   *                 validation.
   *
   * @throws  ArgumentException  If a validation problem is encountered.
   */
  private static void doFinalValidation(final ArgumentParser parser)
          throws ArgumentException
  {
    // Make sure that all required arguments have values.
    for (final Argument a : parser.namedArgs)
    {
      if (a.isRequired() && (! a.isPresent()))
      {
        throw new ArgumentException(ERR_PARSER_MISSING_REQUIRED_ARG.get(
                                         a.getIdentifierString()));
      }
    }


    // Make sure that at least the minimum number of trailing arguments were
    // provided.
    if (parser.trailingArgs.size() < parser.minTrailingArgs)
    {
      throw new ArgumentException(ERR_PARSER_NOT_ENOUGH_TRAILING_ARGS.get(
           parser.commandName, parser.minTrailingArgs,
           parser.trailingArgsPlaceholder));
    }


    // Make sure that there are no dependent argument set conflicts.
    for (final ObjectPair<Argument,Set<Argument>> p :
         parser.dependentArgumentSets)
    {
      final Argument targetArg = p.getFirst();
      if (targetArg.getNumOccurrences() > 0)
      {
        final Set<Argument> argSet = p.getSecond();
        boolean found = false;
        for (final Argument a : argSet)
        {
          if (a.getNumOccurrences() > 0)
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
    for (final Set<Argument> argSet : parser.exclusiveArgumentSets)
    {
      Argument setArg = null;
      for (final Argument a : argSet)
      {
        if (a.getNumOccurrences() > 0)
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
    for (final Set<Argument> argSet : parser.requiredArgumentSets)
    {
      boolean found = false;
      for (final Argument a : argSet)
      {
        if (a.getNumOccurrences() > 0)
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
   * Indicates whether the provided argument is one that indicates that the
   * parser should skip all validation except that performed when assigning
   * values from command-line arguments.  Validation that will be skipped
   * includes ensuring that all required arguments have values, ensuring that
   * the minimum number of trailing arguments were provided, and ensuring that
   * there were no dependent/exclusive/required argument set conflicts.
   *
   * @param  a  The argument for which to make the determination.
   *
   * @return  {@code true} if the provided argument is one that indicates that
   *          final validation should be skipped, or {@code false} if not.
   */
  private static boolean skipFinalValidationBecauseOfArgument(final Argument a)
  {
    // We will skip final validation for all usage arguments except the ones
    // used for interacting with properties and output files.
    if (ARG_NAME_PROPERTIES_FILE_PATH.equals(a.getLongIdentifier()) ||
        ARG_NAME_NO_PROPERTIES_FILE.equals(a.getLongIdentifier()) ||
        ARG_NAME_SUPPRESS_PROPERTIES_FILE_COMMENT.equals(
             a.getLongIdentifier()) ||
        ARG_NAME_OUTPUT_FILE.equals(a.getLongIdentifier()) ||
        ARG_NAME_TEE_OUTPUT.equals(a.getLongIdentifier()))
    {
      return false;
    }

    return a.isUsageArgument();
  }



  /**
   * Performs any appropriate properties file processing for this argument
   * parser.
   *
   * @return  {@code true} if the tool should continue processing, or
   *          {@code false} if it should return immediately.
   *
   * @throws  ArgumentException  If a problem is encountered while attempting
   *                             to parse a properties file or update arguments
   *                             with the values contained in it.
   */
  private boolean handlePropertiesFile()
          throws ArgumentException
  {
    final BooleanArgument noPropertiesFile;
    final FileArgument generatePropertiesFile;
    final FileArgument propertiesFilePath;
    try
    {
      propertiesFilePath = getFileArgument(ARG_NAME_PROPERTIES_FILE_PATH);
      generatePropertiesFile =
           getFileArgument(ARG_NAME_GENERATE_PROPERTIES_FILE);
      noPropertiesFile = getBooleanArgument(ARG_NAME_NO_PROPERTIES_FILE);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      // This should only ever happen if the argument parser has an argument
      // with a name that conflicts with one of the properties file arguments
      // but isn't of the right type.  In this case, we'll assume that no
      // properties file will be used.
      return true;
    }


    // If any of the properties file arguments isn't defined, then we'll assume
    // that no properties file will be used.
    if ((propertiesFilePath == null) || (generatePropertiesFile == null) ||
        (noPropertiesFile == null))
    {
      return true;
    }


    // If the noPropertiesFile argument is present, then don't do anything but
    // make sure that neither of the other arguments was specified.
    if (noPropertiesFile.isPresent())
    {
      if (propertiesFilePath.isPresent())
      {
        throw new ArgumentException(ERR_PARSER_EXCLUSIVE_CONFLICT.get(
             noPropertiesFile.getIdentifierString(),
             propertiesFilePath.getIdentifierString()));
      }
      else if (generatePropertiesFile.isPresent())
      {
        throw new ArgumentException(ERR_PARSER_EXCLUSIVE_CONFLICT.get(
             noPropertiesFile.getIdentifierString(),
             generatePropertiesFile.getIdentifierString()));
      }
      else
      {
        return true;
      }
    }


    // If the generatePropertiesFile argument is present, then make sure the
    // propertiesFilePath argument is not set and generate the output.
    if (generatePropertiesFile.isPresent())
    {
      if (propertiesFilePath.isPresent())
      {
        throw new ArgumentException(ERR_PARSER_EXCLUSIVE_CONFLICT.get(
             generatePropertiesFile.getIdentifierString(),
             propertiesFilePath.getIdentifierString()));
      }
      else
      {
        generatePropertiesFile(
             generatePropertiesFile.getValue().getAbsolutePath());
        return false;
      }
    }


    // If the propertiesFilePath argument is present, then try to make use of
    // the specified file.
    if (propertiesFilePath.isPresent())
    {
      final File propertiesFile = propertiesFilePath.getValue();
      if (propertiesFile.exists() && propertiesFile.isFile())
      {
        handlePropertiesFile(propertiesFilePath.getValue());
      }
      else
      {
        throw new ArgumentException(
             ERR_PARSER_NO_SUCH_PROPERTIES_FILE.get(
                  propertiesFilePath.getIdentifierString(),
                  propertiesFile.getAbsolutePath()));
      }
      return true;
    }


    // We may still use a properties file if the path was specified in either a
    // JVM property or an environment variable.  If both are defined, the JVM
    // property will take precedence.  If a property or environment variable
    // specifies an invalid value, then we'll just ignore it.
    String path = System.getProperty(PROPERTY_DEFAULT_PROPERTIES_FILE_PATH);
    if (path == null)
    {
      path = System.getenv(ENV_DEFAULT_PROPERTIES_FILE_PATH);
    }

    if (path != null)
    {
      final File propertiesFile = new File(path);
      if (propertiesFile.exists() && propertiesFile.isFile())
      {
        handlePropertiesFile(propertiesFile);
      }
    }

    return true;
  }



  /**
   * Write an empty properties file for this argument parser to the specified
   * path.
   *
   * @param  path  The path to the properties file to be written.
   *
   * @throws  ArgumentException  If a problem is encountered while writing the
   *                             properties file.
   */
  private void generatePropertiesFile(final String path)
          throws ArgumentException
  {
    final PrintWriter w;
    try
    {
      w = new PrintWriter(path);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ArgumentException(
           ERR_PARSER_GEN_PROPS_CANNOT_OPEN_FILE.get(path,
                getExceptionMessage(e)),
           e);
    }

    try
    {
      wrapComment(w, INFO_PARSER_GEN_PROPS_HEADER_1.get(commandName));
      w.println('#');
      wrapComment(w,
           INFO_PARSER_GEN_PROPS_HEADER_2.get(commandName,
                ARG_NAME_PROPERTIES_FILE_PATH,
                PROPERTY_DEFAULT_PROPERTIES_FILE_PATH,
                ENV_DEFAULT_PROPERTIES_FILE_PATH, ARG_NAME_NO_PROPERTIES_FILE));
      w.println('#');
      wrapComment(w, INFO_PARSER_GEN_PROPS_HEADER_3.get());
      w.println('#');

      wrapComment(w, INFO_PARSER_GEN_PROPS_HEADER_4.get());
      w.println('#');
      wrapComment(w, INFO_PARSER_GEN_PROPS_HEADER_5.get(commandName));

      for (final Argument a : getNamedArguments())
      {
        writeArgumentProperties(w, null, a);
      }

      for (final SubCommand sc : getSubCommands())
      {
        for (final Argument a : sc.getArgumentParser().getNamedArguments())
        {
          writeArgumentProperties(w, sc, a);
        }
      }
    }
    finally
    {
      w.close();
    }
  }



  /**
   * Writes information about the provided argument to the given writer.
   *
   * @param  w   The writer to which the properties should be written.  It must
   *             not be {@code null}.
   * @param  sc  The subcommand with which the argument is associated.  It may
   *             be {@code null} if the provided argument is a global argument.
   * @param  a   The argument for which to write the properties.  It must not be
   *             {@code null}.
   */
  private void writeArgumentProperties(final PrintWriter w,
                                       final SubCommand sc,
                                       final Argument a)
  {
    if (a.isUsageArgument() || a.isHidden())
    {
      return;
    }

    w.println();
    w.println();
    wrapComment(w, a.getDescription());
    w.println('#');

    final String constraints = a.getValueConstraints();
    if ((constraints != null) && (constraints.length() > 0) &&
        (! (a instanceof BooleanArgument)))
    {
      wrapComment(w, constraints);
      w.println('#');
    }

    final String identifier;
    if (a.getLongIdentifier() != null)
    {
      identifier = a.getLongIdentifier();
    }
    else
    {
      identifier = a.getIdentifierString();
    }

    String placeholder = a.getValuePlaceholder();
    if (placeholder == null)
    {
      if (a instanceof BooleanArgument)
      {
        placeholder = "{true|false}";
      }
      else
      {
        placeholder = "";
      }
    }

    final String propertyName;
    if (sc == null)
    {
      propertyName = commandName + '.' + identifier;
    }
    else
    {
      propertyName = commandName + '.' + sc.getPrimaryName() + '.' + identifier;
    }

    w.println("# " + propertyName + '=' + placeholder);

    if (a.isPresent())
    {
      for (final String s : a.getValueStringRepresentations(false))
      {
        w.println(propertyName + '=' + s);
      }
    }
  }



  /**
   * Wraps the given string and writes it as a comment to the provided writer.
   *
   * @param  w  The writer to use to write the wrapped and commented string.
   * @param  s  The string to be wrapped and written.
   */
  private static void wrapComment(final PrintWriter w, final String s)
  {
    for (final String line : wrapLine(s, 77))
    {
      w.println("# " + line);
    }
  }



  /**
   * Reads the contents of the specified properties file and updates the
   * configured arguments as appropriate.
   *
   * @param  propertiesFile  The properties file to process.
   *
   * @throws  ArgumentException  If a problem is encountered while examining the
   *                             properties file, or while trying to assign a
   *                             property value to a corresponding argument.
   */
  private void handlePropertiesFile(final File propertiesFile)
          throws ArgumentException
  {
    final BufferedReader reader;
    try
    {
      reader = new BufferedReader(new FileReader(propertiesFile));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ArgumentException(
           ERR_PARSER_CANNOT_OPEN_PROP_FILE.get(
                propertiesFile.getAbsolutePath(), getExceptionMessage(e)),
           e);
    }

    try
    {
      // Read all of the lines of the file, ignoring comments and unwrapping
      // properties that span multiple lines.
      boolean lineIsContinued = false;
      int lineNumber = 0;
      final ArrayList<ObjectPair<Integer,StringBuilder>> propertyLines =
           new ArrayList<ObjectPair<Integer,StringBuilder>>(10);
      while (true)
      {
        String line;
        try
        {
          line = reader.readLine();
          lineNumber++;
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new ArgumentException(
               ERR_PARSER_ERROR_READING_PROP_FILE.get(
                    propertiesFile.getAbsolutePath(), getExceptionMessage(e)),
               e);
        }


        // If the line is null, then we've reached the end of the file.  If we
        // expect a previous line to have been continued, then this is an error.
        if (line == null)
        {
          if (lineIsContinued)
          {
            throw new ArgumentException(
                 ERR_PARSER_PROP_FILE_MISSING_CONTINUATION.get(
                      (lineNumber-1), propertiesFile.getAbsolutePath()));
          }
          break;
        }


        // See if the line has any leading whitespace, and if so then trim it
        // off.  If there is leading whitespace, then make sure that we expect
        // the previous line to be continued.
        final int initialLength = line.length();
        line = trimLeading(line);
        final boolean hasLeadingWhitespace = (line.length() < initialLength);
        if (hasLeadingWhitespace && (! lineIsContinued))
        {
          throw new ArgumentException(
               ERR_PARSER_PROP_FILE_UNEXPECTED_LEADING_SPACE.get(
                    propertiesFile.getAbsolutePath(), lineNumber));
        }


        // If the line is empty or starts with "#", then skip it.  But make sure
        // we didn't expect the previous line to be continued.
        if ((line.length() == 0) || line.startsWith("#"))
        {
          if (lineIsContinued)
          {
            throw new ArgumentException(
                 ERR_PARSER_PROP_FILE_MISSING_CONTINUATION.get(
                      (lineNumber-1), propertiesFile.getAbsolutePath()));
          }
          continue;
        }


        // See if the line ends with a backslash and if so then trim it off.
        final boolean hasTrailingBackslash = line.endsWith("\\");
        if (line.endsWith("\\"))
        {
          line = line.substring(0, (line.length() - 1));
        }


        // If the previous line needs to be continued, then append the new line
        // to it.  Otherwise, add it as a new line.
        if (lineIsContinued)
        {
          propertyLines.get(propertyLines.size() - 1).getSecond().append(line);
        }
        else
        {
          propertyLines.add(new ObjectPair<Integer,StringBuilder>(lineNumber,
               new StringBuilder(line)));
        }

        lineIsContinued = hasTrailingBackslash;
      }


      // Parse all of the lines into a map of identifiers and their
      // corresponding values.
      propertiesFileUsed = propertiesFile;
      if (propertyLines.isEmpty())
      {
        return;
      }

      final HashMap<String,ArrayList<String>> propertyMap =
           new HashMap<String,ArrayList<String>>(propertyLines.size());
      for (final ObjectPair<Integer,StringBuilder> p : propertyLines)
      {
        final String line = p.getSecond().toString();
        final int equalPos = line.indexOf('=');
        if (equalPos <= 0)
        {
          throw new ArgumentException(ERR_PARSER_MALFORMED_PROP_LINE.get(
               propertiesFile.getAbsolutePath(), p.getFirst(), line));
        }

        final String propertyName = line.substring(0, equalPos).trim();
        final String propertyValue = line.substring(equalPos+1).trim();
        if (propertyValue.length() == 0)
        {
          // The property doesn't have a value, so we can ignore it.
          continue;
        }


        // An argument can have multiple identifiers, and we will allow any of
        // them to be used to reference it.  To deal with this, we'll map the
        // argument identifier to its corresponding argument and then use the
        // preferred identifier for that argument in the map.  The same applies
        // to subcommand names.
        boolean prefixedWithToolName = false;
        boolean prefixedWithSubCommandName = false;
        Argument a = getNamedArgument(propertyName);
        if (a == null)
        {
          // It could be that the argument name was prefixed with the tool name.
          // Check to see if that was the case.
          if (propertyName.startsWith(commandName + '.'))
          {
            prefixedWithToolName = true;

            String basePropertyName =
                 propertyName.substring(commandName.length()+1);
            a = getNamedArgument(basePropertyName);

            if (a == null)
            {
              final int periodPos = basePropertyName.indexOf('.');
              if (periodPos > 0)
              {
                final String subCommandName =
                     basePropertyName.substring(0, periodPos);
                if ((selectedSubCommand != null) &&
                    selectedSubCommand.hasName(subCommandName))
                {
                  prefixedWithSubCommandName = true;
                  basePropertyName = basePropertyName.substring(periodPos+1);
                  a = selectedSubCommand.getArgumentParser().getNamedArgument(
                       basePropertyName);
                }
              }
              else if (selectedSubCommand != null)
              {
                a = selectedSubCommand.getArgumentParser().getNamedArgument(
                     basePropertyName);
              }
            }
          }
          else if (selectedSubCommand != null)
          {
            a = selectedSubCommand.getArgumentParser().getNamedArgument(
                 propertyName);
          }
        }

        if (a == null)
        {
          // This could mean that there's a typo in the property name, but it's
          // more likely the case that the property is for a different tool.  In
          // either case, we'll ignore it.
          continue;
        }

        final String canonicalPropertyName;
        if (prefixedWithToolName)
        {
          if (prefixedWithSubCommandName)
          {
            canonicalPropertyName = commandName + '.' +
                 selectedSubCommand.getPrimaryName() + '.' +
                 a.getIdentifierString();
          }
          else
          {
            canonicalPropertyName = commandName + '.' + a.getIdentifierString();
          }
        }
        else
        {
          canonicalPropertyName = a.getIdentifierString();
        }

        ArrayList<String> valueList = propertyMap.get(canonicalPropertyName);
        if (valueList == null)
        {
          valueList = new ArrayList<String>(5);
          propertyMap.put(canonicalPropertyName, valueList);
        }
        valueList.add(propertyValue);
      }


      // Iterate through all of the named arguments for the argument parser and
      // see if we should use the properties to assign values to any of the
      // arguments that weren't provided on the command line.
      setArgsFromPropertiesFile(propertyMap, false);


      // If there is a selected subcommand, then iterate through all of its
      // arguments.
      if (selectedSubCommand != null)
      {
        setArgsFromPropertiesFile(propertyMap, true);
      }
    }
    finally
    {
      try
      {
        reader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }



  /**
   * Sets the values of any arguments not provided on the command line but
   * defined in the properties file.
   *
   * @param  propertyMap    A map of properties read from the properties file.
   * @param  useSubCommand  Indicates whether to use the argument parser
   *                        associated with the selected subcommand rather than
   *                        the global argument parser.
   *
   * @throws  ArgumentException  If a problem is encountered while examining the
   *                             properties file, or while trying to assign a
   *                             property value to a corresponding argument.
   */
  private void setArgsFromPropertiesFile(
                    final Map<String,ArrayList<String>> propertyMap,
                    final boolean useSubCommand)
          throws ArgumentException
  {
    final ArgumentParser p;
    if (useSubCommand)
    {
      p = selectedSubCommand.getArgumentParser();
    }
    else
    {
      p = this;
    }


    for (final Argument a : p.namedArgs)
    {
      if (a.getNumOccurrences() > 0)
      {
        // The argument was provided on the command line, and that will always
        // override anything that might be in the properties file.
        continue;
      }


      // If we should use a subcommand, then see if the properties file has a
      // property that is specific to the selected subcommand.  Then fall back
      // to a property that is specific to the tool, and finally fall back to
      // checking for a set of values that are generic to any tool that has an
      // argument with that name.
      List<String> values = null;
      if (useSubCommand)
      {
        values = propertyMap.get(commandName + '.' +
             selectedSubCommand.getPrimaryName()  + '.' +
             a.getIdentifierString());
      }

      if (values == null)
      {
        values = propertyMap.get(commandName + '.' + a.getIdentifierString());
      }

      if (values == null)
      {
        values = propertyMap.get(a.getIdentifierString());
      }

      if (values != null)
      {
        for (final String value : values)
        {
          if (a instanceof BooleanArgument)
          {
            // We'll treat this as a BooleanValueArgument.
            final BooleanValueArgument bva = new BooleanValueArgument(
                 a.getShortIdentifier(), a.getLongIdentifier(), false, null,
                 a.getDescription());
            bva.addValue(value);
            if (bva.getValue())
            {
              a.incrementOccurrences();
              argumentsSetFromPropertiesFile.add(a.getIdentifierString());
            }
          }
          else
          {
            a.addValue(value);
            a.incrementOccurrences();

            argumentsSetFromPropertiesFile.add(a.getIdentifierString());
            if (a.isSensitive())
            {
              argumentsSetFromPropertiesFile.add("***REDACTED***");
            }
            else
            {
              argumentsSetFromPropertiesFile.add(value);
            }
          }
        }
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
    // If a subcommand was selected, then provide usage specific to that
    // subcommand.
    if (selectedSubCommand != null)
    {
      return getSubCommandUsage(maxWidth);
    }

    // First is a description of the command.
    final ArrayList<String> lines = new ArrayList<String>(100);
    lines.addAll(wrapLine(commandDescription, maxWidth));
    lines.add("");


    // If the tool supports subcommands, and if there are fewer than 10
    // subcommands, then display them inline.
    if ((! subCommands.isEmpty()) && (subCommands.size() < 10))
    {
      lines.add(INFO_USAGE_SUBCOMMANDS_HEADER.get());
      lines.add("");

      for (final SubCommand sc : subCommands)
      {
        final StringBuilder nameBuffer = new StringBuilder();
        nameBuffer.append("  ");

        final Iterator<String> nameIterator = sc.getNames(false).iterator();
        while (nameIterator.hasNext())
        {
          nameBuffer.append(nameIterator.next());
          if (nameIterator.hasNext())
          {
            nameBuffer.append(", ");
          }
        }
        lines.add(nameBuffer.toString());

        for (final String descriptionLine :
             wrapLine(sc.getDescription(), (maxWidth - 4)))
        {
          lines.add("    " + descriptionLine);
        }
        lines.add("");
      }
    }


    // Next comes the usage.  It may include neither, either, or both of the
    // set of options and trailing arguments.
    if (! subCommands.isEmpty())
    {
      lines.addAll(wrapLine(INFO_USAGE_SUBCOMMAND_USAGE.get(commandName),
                            maxWidth));
    }
    else if (namedArgs.isEmpty())
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
    }

    if (! namedArgs.isEmpty())
    {
      lines.add("");
      lines.add(INFO_USAGE_OPTIONS_INCLUDE.get());


      // If there are any argument groups, then collect the arguments in those
      // groups.
      boolean hasRequired = false;
      final LinkedHashMap<String,List<Argument>> argumentsByGroup =
           new LinkedHashMap<String,List<Argument>>(10);
      final ArrayList<Argument> argumentsWithoutGroup =
           new ArrayList<Argument>(namedArgs.size());
      final ArrayList<Argument> usageArguments =
           new ArrayList<Argument>(namedArgs.size());
      for (final Argument a : namedArgs)
      {
        if (a.isHidden())
        {
          // This argument shouldn't be included in the usage output.
          continue;
        }

        if (a.isRequired() && (! a.hasDefaultValue()))
        {
          hasRequired = true;
        }

        final String argumentGroup = a.getArgumentGroupName();
        if (argumentGroup == null)
        {
          if (a.isUsageArgument())
          {
            usageArguments.add(a);
          }
          else
          {
            argumentsWithoutGroup.add(a);
          }
        }
        else
        {
          List<Argument> groupArgs = argumentsByGroup.get(argumentGroup);
          if (groupArgs == null)
          {
            groupArgs = new ArrayList<Argument>(10);
            argumentsByGroup.put(argumentGroup, groupArgs);
          }

          groupArgs.add(a);
        }
      }


      // Iterate through the defined argument groups and display usage
      // information for each of them.
      for (final Map.Entry<String,List<Argument>> e :
           argumentsByGroup.entrySet())
      {
        lines.add("");
        lines.add("  " + e.getKey());
        lines.add("");
        for (final Argument a : e.getValue())
        {
          getArgUsage(a, lines, true, maxWidth);
        }
      }

      if (! argumentsWithoutGroup.isEmpty())
      {
        if (argumentsByGroup.isEmpty())
        {
          for (final Argument a : argumentsWithoutGroup)
          {
            getArgUsage(a, lines, false, maxWidth);
          }
        }
        else
        {
          lines.add("");
          lines.add("  " + INFO_USAGE_UNGROUPED_ARGS.get());
          lines.add("");
          for (final Argument a : argumentsWithoutGroup)
          {
            getArgUsage(a, lines, true, maxWidth);
          }
        }
      }

      if (! usageArguments.isEmpty())
      {
        if (argumentsByGroup.isEmpty())
        {
          for (final Argument a : usageArguments)
          {
            getArgUsage(a, lines, false, maxWidth);
          }
        }
        else
        {
          lines.add("");
          lines.add("  " + INFO_USAGE_USAGE_ARGS.get());
          lines.add("");
          for (final Argument a : usageArguments)
          {
            getArgUsage(a, lines, true, maxWidth);
          }
        }
      }

      if (hasRequired)
      {
        lines.add("");
        if (argumentsByGroup.isEmpty())
        {
          lines.add("* " + INFO_USAGE_ARG_IS_REQUIRED.get());
        }
        else
        {
          lines.add("  * " + INFO_USAGE_ARG_IS_REQUIRED.get());
        }
      }
    }

    return lines;
  }



  /**
   * Retrieves lines that make up the usage information for the selected
   * subcommand.
   *
   * @param  maxWidth  The maximum line width to use for the output.  If this is
   *                   less than or equal to zero, then no wrapping will be
   *                   performed.
   *
   * @return  The lines that make up the usage information for the selected
   *          subcommand.
   */
  private List<String> getSubCommandUsage(final int maxWidth)
  {
    // First is a description of the subcommand.
    final ArrayList<String> lines = new ArrayList<String>(100);
    lines.addAll(wrapLine(selectedSubCommand.getDescription(), maxWidth));
    lines.add("");

    // Next comes the usage.
    lines.addAll(wrapLine(
         INFO_SUBCOMMAND_USAGE_OPTIONS.get(commandName,
              selectedSubCommand.getPrimaryName()),
         maxWidth));


    final ArgumentParser parser = selectedSubCommand.getArgumentParser();
    if (! parser.namedArgs.isEmpty())
    {
      lines.add("");
      lines.add(INFO_USAGE_OPTIONS_INCLUDE.get());


      // If there are any argument groups, then collect the arguments in those
      // groups.
      boolean hasRequired = false;
      final LinkedHashMap<String,List<Argument>> argumentsByGroup =
           new LinkedHashMap<String,List<Argument>>(10);
      final ArrayList<Argument> argumentsWithoutGroup =
           new ArrayList<Argument>(parser.namedArgs.size());
      final ArrayList<Argument> usageArguments =
           new ArrayList<Argument>(parser.namedArgs.size());
      for (final Argument a : parser.namedArgs)
      {
        if (a.isHidden())
        {
          // This argument shouldn't be included in the usage output.
          continue;
        }

        if (a.isRequired() && (! a.hasDefaultValue()))
        {
          hasRequired = true;
        }

        final String argumentGroup = a.getArgumentGroupName();
        if (argumentGroup == null)
        {
          if (a.isUsageArgument())
          {
            usageArguments.add(a);
          }
          else
          {
            argumentsWithoutGroup.add(a);
          }
        }
        else
        {
          List<Argument> groupArgs = argumentsByGroup.get(argumentGroup);
          if (groupArgs == null)
          {
            groupArgs = new ArrayList<Argument>(10);
            argumentsByGroup.put(argumentGroup, groupArgs);
          }

          groupArgs.add(a);
        }
      }


      // Iterate through the defined argument groups and display usage
      // information for each of them.
      for (final Map.Entry<String,List<Argument>> e :
           argumentsByGroup.entrySet())
      {
        lines.add("");
        lines.add("  " + e.getKey());
        lines.add("");
        for (final Argument a : e.getValue())
        {
          getArgUsage(a, lines, true, maxWidth);
        }
      }

      if (! argumentsWithoutGroup.isEmpty())
      {
        if (argumentsByGroup.isEmpty())
        {
          for (final Argument a : argumentsWithoutGroup)
          {
            getArgUsage(a, lines, false, maxWidth);
          }
        }
        else
        {
          lines.add("");
          lines.add("  " + INFO_USAGE_UNGROUPED_ARGS.get());
          lines.add("");
          for (final Argument a : argumentsWithoutGroup)
          {
            getArgUsage(a, lines, true, maxWidth);
          }
        }
      }

      if (! usageArguments.isEmpty())
      {
        if (argumentsByGroup.isEmpty())
        {
          for (final Argument a : usageArguments)
          {
            getArgUsage(a, lines, false, maxWidth);
          }
        }
        else
        {
          lines.add("");
          lines.add("  " + INFO_USAGE_USAGE_ARGS.get());
          lines.add("");
          for (final Argument a : usageArguments)
          {
            getArgUsage(a, lines, true, maxWidth);
          }
        }
      }

      if (hasRequired)
      {
        lines.add("");
        if (argumentsByGroup.isEmpty())
        {
          lines.add("* " + INFO_USAGE_ARG_IS_REQUIRED.get());
        }
        else
        {
          lines.add("  * " + INFO_USAGE_ARG_IS_REQUIRED.get());
        }
      }
    }

    return lines;
  }



  /**
   * Adds usage information for the provided argument to the given list.
   *
   * @param  a         The argument for which to get the usage information.
   * @param  lines     The list to which the resulting lines should be added.
   * @param  indent    Indicates whether to indent each line.
   * @param  maxWidth  The maximum width of each line, in characters.
   */
  private static void getArgUsage(final Argument a, final List<String> lines,
                                  final boolean indent, final int maxWidth)
  {
    final StringBuilder argLine = new StringBuilder();
    if (indent && (maxWidth > 10))
    {
      if (a.isRequired() && (! a.hasDefaultValue()))
      {
        argLine.append("  * ");
      }
      else
      {
        argLine.append("    ");
      }
    }
    else if (a.isRequired() && (! a.hasDefaultValue()))
    {
      argLine.append("* ");
    }

    boolean first = true;
    for (final Character c : a.getShortIdentifiers(false))
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

    for (final String s : a.getLongIdentifiers(false))
    {
      if (first)
      {
        argLine.append("--");
        first = false;
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

    // If we need to wrap the argument line, then align the dashes on the left
    // edge.
    int subsequentLineWidth = maxWidth - 4;
    if (subsequentLineWidth < 4)
    {
      subsequentLineWidth = maxWidth;
    }
    final List<String> identifierLines =
         wrapLine(argLine.toString(), maxWidth, subsequentLineWidth);
    for (int i=0; i < identifierLines.size(); i++)
    {
      if (i == 0)
      {
        lines.add(identifierLines.get(0));
      }
      else
      {
        lines.add("    " + identifierLines.get(i));
      }
    }


    // The description should be wrapped, if necessary.  We'll also want to
    // indent it (unless someone chose an absurdly small wrap width) to make
    // it stand out from the argument lines.
    final String description = a.getDescription();
    if (maxWidth > 10)
    {
      final String indentString;
      if (indent)
      {
        indentString = "        ";
      }
      else
      {
        indentString = "    ";
      }

      final List<String> descLines = wrapLine(description,
           (maxWidth-indentString.length()));
      for (final String s : descLines)
      {
        lines.add(indentString + s);
      }
    }
    else
    {
      lines.addAll(wrapLine(description, maxWidth));
    }
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
    buffer.append("', minTrailingArgs=");
    buffer.append(minTrailingArgs);
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

    buffer.append('}');

    if (! subCommands.isEmpty())
    {
      buffer.append(", subCommands={");

      final Iterator<SubCommand> subCommandIterator = subCommands.iterator();
      while (subCommandIterator.hasNext())
      {
        subCommandIterator.next().toString(buffer);
        if (subCommandIterator.hasNext())
        {
          buffer.append(", ");
        }
      }

      buffer.append('}');
    }

    buffer.append(')');
  }
}
