/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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



import java.util.List;
import java.util.ArrayList;
import java.io.Serializable;



/**
 * This class provides access to a form of a command-line argument that is
 * safe to use in a shell.  It includes both forms for both Unix (bash shell
 * specifically) and Windows, since there are differences between the two
 * platforms.  Quoting of arguments is performed with the following goals:
 *
 * <UL>
 *   <LI>The same form should be used for both Unix and Windows whenever
 *       possible.</LI>
 *   <LI>If the same form cannot be used for both platforms, then make it
 *       as easy as possible to convert the form to the other platform.</LI>
 *   <LI>If neither platform requires quoting of an argument, then it is not
 *       quoted.</LI>
 * </UL>
 *
 * To that end, here is the approach that we've taken:
 *
 * <UL>
 *   <LI>Characters in the output are never escaped with the \ character
 *       because Windows does not understand \ used to escape.</LI>
 *   <LI>On Unix, double-quotes are used to quote whenever possible since
 *       Windows does not treat single quotes specially.</LI>
 *   <LI>If a String needs to be quoted on either platform, then it is quoted
 *       on both.  If it needs to be quoted with single-quotes on Unix, then
 *       it will be quoted with double quotes on Windows.
 *   <LI>On Unix, single-quote presents a problem if it's included in a
 *       string that needs to be singled-quoted, for instance one that includes
 *       the $ or ! characters.  In this case, we have to wrap it in
 *       double-quotes outside of the single-quotes.  For instance, Server's!
 *       would end up as 'Server'"'"'s!'.</LI>
 *   <LI>On Windows, double-quotes present a problem.  They have to be
 *       escaped using two double-quotes inside of a double-quoted string.
 *       For instance "Quoted" ends up as """Quoted""".</LI>
 * </UL>
 *
 * All of the forms can be unambiguously parsed using the
 * {@link #parseExampleCommandLine} method regardless of the platform.  This
 * method can be used when needing to parse a command line that was generated
 * by this class outside of a shell environment, e.g. if the full command line
 * was read from a file.  Special characters that are escaped include |, &amp;,
 * ;, (, ), !, ", ', *, ?, $, and `.
 */
@ThreadSafety(level = ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ExampleCommandLineArgument implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2468880329239320437L;



  // The argument that was passed in originally.
  @NotNull private final String rawForm;

  // The Unix form of the argument.
  @NotNull private final String unixForm;

  // The Windows form of the argument.
  @NotNull private final String windowsForm;



  /**
   * Private constructor.
   *
   * @param  rawForm      The original raw form of the command line argument.
   * @param  unixForm     The Unix form of the argument.
   * @param  windowsForm  The Windows form of the argument.
   */
  private ExampleCommandLineArgument(@NotNull final String rawForm,
                                     @NotNull final String unixForm,
                                     @NotNull final String windowsForm)
  {
    this.rawForm = rawForm;
    this.unixForm     = unixForm;
    this.windowsForm  = windowsForm;
  }



  /**
   * Return the original, unquoted raw form of the argument.  This is what
   * was passed into the {@link #getCleanArgument} method.
   *
   * @return  The original, unquoted form of the argument.
   */
  @NotNull()
  public String getRawForm()
  {
    return rawForm;
  }



  /**
   * Return the form of the argument that is safe to use in a Unix command
   * line shell.
   *
   * @return  The form of the argument that is safe to use in a Unix command
   *          line shell.
   */
  @NotNull()
  public String getUnixForm()
  {
    return unixForm;
  }



  /**
   * Return the form of the argument that is safe to use in a Windows command
   * line shell.
   *
   * @return  The form of the argument that is safe to use in a Windows command
   *          line shell.
   */
  @NotNull()
  public String getWindowsForm()
  {
    return windowsForm;
  }



  /**
   * Return the form of the argument that is safe to use in the command line
   * shell of the current operating system platform.
   *
   * @return  The form of the argument that is safe to use in a command line
   *          shell of the current operating system platform.
   */
  @NotNull()
  public String getLocalForm()
  {
    if (StaticUtils.isWindows())
    {
      return getWindowsForm();
    }
    else
    {
      return getUnixForm();
    }
  }



  /**
   * Return a clean form of the specified argument that can be used directly
   * on the command line.
   *
   * @param  argument  The raw argument to convert into a clean form that can
   *                   be used directly on the command line.
   *
   * @return  The ExampleCommandLineArgument for the specified argument.
   */
  @NotNull()
  public static ExampleCommandLineArgument getCleanArgument(
                                                @NotNull final String argument)
  {
    return new ExampleCommandLineArgument(argument,
                                          getUnixForm(argument),
                                          getWindowsForm(argument));
  }



  /**
   * Return a clean form of the specified argument that can be used directly
   * on a Unix command line.
   *
   * @param  argument  The raw argument to convert into a clean form that can
   *                   be used directly on the Unix command line.
   *
   * @return  A form of the specified argument that is clean for us on a Unix
   *          command line.
   */
  @NotNull()
  public static String getUnixForm(@NotNull final String argument)
  {
    Validator.ensureNotNull(argument);

    final QuotingRequirements requirements = getRequiredUnixQuoting(argument);

    String quotedArgument = argument;
    if (requirements.requiresSingleQuotesOnUnix())
    {
      if (requirements.includesSingleQuote())
      {
        // On the primary Unix shells (e.g. bash), single-quote cannot be
        // included in a single-quoted string.  So it has to be specified
        // outside of the quoted part, and has to be included in "" itself.
        quotedArgument = quotedArgument.replace("'", "'\"'\"'");
      }
      quotedArgument = '\'' + quotedArgument + '\'';
    }
    else if (requirements.requiresDoubleQuotesOnUnix())
    {
      quotedArgument = '"' + quotedArgument + '"';
    }

    return quotedArgument;
  }



  /**
   * Return a clean form of the specified argument that can be used directly
   * on a Windows command line.
   *
   * @param  argument  The raw argument to convert into a clean form that can
   *                   be used directly on the Windows command line.
   *
   * @return  A form of the specified argument that is clean for us on a Windows
   *          command line.
   */
  @NotNull()
  public static String getWindowsForm(@NotNull final String argument)
  {
    Validator.ensureNotNull(argument);

    final QuotingRequirements requirements = getRequiredUnixQuoting(argument);

    String quotedArgument = argument;

    // Windows only supports double-quotes.  They are treated much more like
    // single-quotes on Unix.  Only " needs to be escaped, and it's done by
    // repeating it, i.e. """"" gets passed into the program as just "
    if (requirements.requiresSingleQuotesOnUnix() ||
        requirements.requiresDoubleQuotesOnUnix())
    {
      if (requirements.includesDoubleQuote())
      {
        quotedArgument = quotedArgument.replace("\"", "\"\"");
      }
      quotedArgument = '"' + quotedArgument + '"';
    }

    return quotedArgument;
  }



  /**
   * Return a list of raw parameters that were parsed from the specified String.
   * This can be used to undo the quoting that was done by
   * {@link #getCleanArgument}.  It perfectly handles any String that was
   * passed into this method, but it won't behave exactly as any single shell
   * behaves because they aren't consistent.  For instance, it will never
   * treat \\ as an escape character.
   *
   * @param  exampleCommandLine  The command line to parse.
   *
   * @return  A list of raw arguments that were parsed from the specified
   *          example usage command line.
   */
  @NotNull()
  public static List<String> parseExampleCommandLine(
                                 @NotNull final String exampleCommandLine)
  {
    Validator.ensureNotNull(exampleCommandLine);

    boolean inDoubleQuote = false;
    boolean inSingleQuote = false;

    final List<String> args = new ArrayList<>(20);

    StringBuilder currentArg = new StringBuilder();
    boolean inArg = false;
    for (int i = 0; i < exampleCommandLine.length(); i++) {
      final Character c = exampleCommandLine.charAt(i);

      Character nextChar = null;
      if (i < (exampleCommandLine.length() - 1))
      {
        nextChar = exampleCommandLine.charAt(i + 1);
      }

      if (inDoubleQuote)
      {
        if (c == '"')
        {
          if ((nextChar != null) && (nextChar == '"'))
          {
            // Handle the special case on Windows where a " is escaped inside
            // of double-quotes using "", i.e. to get " passed into the program,
            // """" must be specified.
            currentArg.append('\"');
            i++;
          }
          else
          {
            inDoubleQuote = false;
          }
        }
        else
        {
          currentArg.append(c);
        }
      }
      else if (inSingleQuote)
      {
        if (c == '\'')
        {
          inSingleQuote = false;
        }
        else
        {
          currentArg.append(c);
        }
      }
      else if (c == '"')
      {
        inDoubleQuote = true;
        inArg = true;
      }
      else if (c == '\'')
      {
        inSingleQuote = true;
        inArg = true;
      }
      else if ((c == ' ') || (c == '\t'))
      {
        if (inArg)
        {
          args.add(currentArg.toString());
          currentArg = new StringBuilder();
          inArg = false;
        }
      }
      else
      {
        currentArg.append(c);
        inArg = true;
      }
    }

    if (inArg)
    {
      args.add(currentArg.toString());
    }

    return args;
  }



  /**
   * Examines the specified argument to determine how it will need to be
   * quoted.
   *
   * @param  argument  The argument to examine.
   *
   * @return  The QuotingRequirements for the specified argument.
   */
  @NotNull()
  private static QuotingRequirements getRequiredUnixQuoting(
                                         @NotNull final String argument)
  {
    boolean requiresDoubleQuotes = false;
    boolean requiresSingleQuotes = false;
    boolean includesDoubleQuote = false;
    boolean includesSingleQuote = false;

    if (argument.isEmpty())
    {
      requiresDoubleQuotes = true;
    }

    for (int i=0; i < argument.length(); i++)
    {
      final char c = argument.charAt(i);
      switch (c)
      {
        case '"':
          includesDoubleQuote = true;
          requiresSingleQuotes = true;
          break;
        case '\\':
        case '!':
        case '`':
        case '$':
        case '@':
        case '*':
          requiresSingleQuotes = true;
          break;

        case '\'':
          includesSingleQuote = true;
          requiresDoubleQuotes = true;
          break;
        case ' ':
        case '|':
        case '&':
        case ';':
        case '(':
        case ')':
        case '<':
        case '>':
          requiresDoubleQuotes = true;
          break;

        case ',':
        case '=':
        case '-':
        case '_':
        case ':':
        case '.':
        case '/':
          // These are safe, so just ignore them.
          break;

        default:
          if (((c >= 'a') && (c <= 'z')) ||
              ((c >= 'A') && (c <= 'Z')) ||
              ((c >= '0') && (c <= '9')))
          {
            // These are safe, so just ignore them.
          }
          else
          {
            requiresDoubleQuotes = true;
          }
      }
    }

    if (requiresSingleQuotes)
    {
      // Single-quoting trumps double-quotes.
      requiresDoubleQuotes = false;
    }

    return new QuotingRequirements(requiresSingleQuotes, requiresDoubleQuotes,
                                   includesSingleQuote, includesDoubleQuote);
  }
}
