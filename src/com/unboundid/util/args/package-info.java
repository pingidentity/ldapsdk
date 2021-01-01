/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



/**
 * This package contains a set of classes that may be used to perform
 * command line argument parsing.  Arguments can have a number of properties,
 * including:
 * <BR><BR>
 * <UL>
 *   <LI>A short identifier, which is a single character and is used by
 *       prefixing it with a single dash on the command line (e.g., "-H").</LI>
 *   <LI>A long identifier, which is a string and is used by prefixing it with
 *       two dashes on the command line (e.g., "--help").  Long arguments will
 *       be treated in a case-insensitive manner.</LI>
 *   <LI>A description, which provides basic information about the purpose of
 *       the argument.  This makes it possible for the argument parser to
 *       generate usage information.</LI>
 *   <LI>A flag that indicates whether the argument takes a value.  If it does,
 *       then it should also include a placeholder string to indicate what that
 *       value is supposed to be in the usage information.</LI>
 *   <LI>A flag that indicates whether the argument is required to be
 *       provided.</LI>
 *   <LI>A flag that indicates whether the argument is allowed to be provided
 *       multiple times.  This can be useful for arguments that are allowed to
 *       be provided with multiple values, or for cases in which having an
 *       argument provided multiple times amplifies its meaning (e.g., "-v"
 *       enables basic debugging, whereas "-v -v -v" enables the most verbose
 *       debugging).</LI>
 *   <LI>A flag that indicates whether the argument is hidden.  If an argument
 *       is hidden, it may be provided on the command line, but it will not be
 *       displayed in usage information.</LI>
 * </UL>
 * <BR><BR>
 * If an argument takes a value, then it may be separated from the short or long
 * identifier using a space, or an equal sign for long identifiers (e.g.,
 * "-h server.example.com", "--hostname server.example.com", or
 * "--hostname=server.example.com").  In addition, if a short identifier is
 * provided by itself without being concatenated with any other short
 * identifiers, then the value may be directly appended to the short identifier
 * (e.g., "-hserver.example.com").  Note that it is not possible for an argument
 * to optionally take a value.  If an argument is configured to take a value,
 * then it can never be provided on the command line without one, and if an
 * argument is not configured to take a value, then it can never be provided
 * with one.
 * <BR><BR>
 * Arguments are generally separated from each other with one or more spaces.
 * However, if there are multiple arguments that do not take values, then it is
 * possible to concatenate their short identifiers together and prefix the
 * resulting string with a single dash (e.g., "-abcd" would be interpreted as
 * "-a -b -c -d").  This is only allowed for short identifiers, and only for the
 * case in which none of them take values.
 * <BR><BR>
 * It is possible to define relationships between named arguments.  It is
 * possible to indicate that at most one of a specified set of arguments is
 * allowed to be provided (i.e., that those arguments are not allowed to be used
 * together).  It is also possible to indicate that at least one of a specified
 * set of arguments must be provided.  If the same set of arguments is included
 * in both classifications, then exactly one of those arguments must be
 * provided.
 * <BR><BR>
 * In addition to named arguments, it is also possible to indicate that a
 * command accepts unnamed trailing arguments.  In this case, no automatic
 * validation will be performed for those trailing arguments (with the optional
 * exception of enforcing a limit on the maximum allowed number of such
 * arguments), and it is up to the application to parse and interpret them.
 * The first argument which is not the value for the previous argument and does
 * not start with one or two dashes will be considered the first trailing
 * argument, and all arguments after that (regardless of whether they start
 * with dashes) will also be considered trailing arguments.  Additionally, if
 * an argument of "--" is provided by itself, then it will serve to mark as the
 * end of the named arguments, and any arguments provided after that will be
 * considered unnamed trailing arguments.
 */
package com.unboundid.util.args;
