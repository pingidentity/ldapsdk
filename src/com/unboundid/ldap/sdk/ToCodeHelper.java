/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;


import java.util.Iterator;
import java.util.List;

import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a utility that can help generate code for use in the
 * output of {@code toCode} methods.
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ToCodeHelper
{
  /**
   * Prevent this class from being instantiated.
   */
  private ToCodeHelper()
  {
    // No implementation is required.
  }



  /**
   * Generates an appropriate set of code lines for a method or constructor
   * invocation.
   *
   * @param  lineList      The list of lines to which the generated code will
   *                       be added.  It must not be {@code null}.
   * @param  indentSpaces  The number of spaces to indent from the left margin.
   * @param  returnType    The name of the data type for the variable to create
   *                       when assigning the return value for the method.
   *                       It must be {@code null} if the {@code variableName}
   *                       argument is null.  It may be {@code null} if the
   *                       variable type is assumed to have already been
   *                       defined.
   * @param  variableName  The name of the variable to which the method return
   *                       value should be assigned.  It may be {@code null} if
   *                       no variable assignment should be performed.
   * @param  methodName    The name of the method to invoke.  If the generated
   *                       code is for a constructor invocation, then the
   *                       class name should be preceded by "new ".  If the
   *                       generated code is for a static method, then the
   *                       method name should be preceded by the class name and
   *                       a period.  If the generated code is for a non-static
   *                       method, then the method name should be preceded by
   *                       the variable name for an instance of that class and
   *                       a period.  It must not be {@code null}.
   * @param  methodArgs    The set of arguments passed to the generated method.
   *                       It may be {@code null} or empty if no arguments are
   *                       needed.
   */
  public static void generateMethodCall(@NotNull final List<String> lineList,
                          final int indentSpaces,
                          @Nullable final String returnType,
                          @Nullable final String variableName,
                          @NotNull final String methodName,
                          @Nullable final ToCodeArgHelper... methodArgs)
  {
    generateMethodCall(lineList, indentSpaces, returnType, variableName,
         methodName, StaticUtils.toList(methodArgs));
  }



  /**
   * Generates an appropriate set of code lines for a method or constructor
   * invocation.
   *
   * @param  lineList      The list of lines to which the generated code will
   *                       be added.  It must not be {@code null}.
   * @param  indentSpaces  The number of spaces to indent from the left margin.
   * @param  returnType    The name of the data type for the variable to create
   *                       when assigning the return value for the method.
   *                       It must be {@code null} if the {@code variableName}
   *                       argument is null.  It may be {@code null} if the
   *                       variable type is assumed to have already been
   *                       defined.
   * @param  variableName  The name of the variable to which the method return
   *                       value should be assigned.  It may be {@code null} if
   *                       no variable assignment should be performed.
   * @param  methodName    The name of the method to invoke.  If the generated
   *                       code is for a constructor invocation, then the
   *                       class name should be preceded by "new ".  If the
   *                       generated code is for a static method, then the
   *                       method name should be preceded by the class name and
   *                       a period.  If the generated code is for a non-static
   *                       method, then the method name should be preceded by
   *                       the variable name for an instance of that class and
   *                       a period.  It must not be {@code null}.
   * @param  methodArgs    The set of arguments passed to the generated method.
   *                       It may be {@code null} or empty if no arguments are
   *                       needed.
   */
  public static void generateMethodCall(@NotNull final List<String> lineList,
                          final int indentSpaces,
                          @Nullable final String returnType,
                          @Nullable final String variableName,
                          @NotNull final String methodName,
                          @Nullable final List<ToCodeArgHelper> methodArgs)
  {
    final StringBuilder buffer = new StringBuilder();

    // Create a string that will be used for the initial indent.
    for (int i=0; i < indentSpaces; i++)
    {
      buffer.append(' ');
    }
    final String indent = buffer.toString();

    if (returnType != null)
    {
      buffer.append(returnType);
      buffer.append(' ');
    }

    if (variableName != null)
    {
      buffer.append(variableName);
      buffer.append(" = ");
    }

    buffer.append(methodName);
    buffer.append('(');

    if ((methodArgs == null) || methodArgs.isEmpty())
    {
      buffer.append(");");
      lineList.add(buffer.toString());
    }
    else
    {
      lineList.add(buffer.toString());

      final Iterator<ToCodeArgHelper> argIterator = methodArgs.iterator();
      while (argIterator.hasNext())
      {
        final ToCodeArgHelper arg = argIterator.next();

        boolean firstLine = true;
        final Iterator<String> argLineIterator = arg.getLines().iterator();
        while (argLineIterator.hasNext())
        {
          buffer.setLength(0);
          buffer.append(indent);
          buffer.append("     ");
          buffer.append(argLineIterator.next());

          if (! argLineIterator.hasNext())
          {
            if (argIterator.hasNext())
            {
              buffer.append(',');
            }
            else
            {
              buffer.append(");");
            }
          }

          if (firstLine)
          {
            firstLine = false;
            final String comment = arg.getComment();
            if (comment != null)
            {
              buffer.append(" // ");
              buffer.append(comment);
            }
          }

          lineList.add(buffer.toString());
        }
      }
    }
  }



  /**
   * Generates an appropriate set of code lines for a variable assignment.
   *
   * @param  lineList      The list of lines to which the generated code will
   *                       be added.  It must not be {@code null}.
   * @param  indentSpaces  The number of spaces to indent from the left margin.
   * @param  dataType      The name of the data type for the variable to create.
   *                       It may be {@code null} if the variable type is
   *                       assumed to have already been defined.
   * @param  variableName  The name of the variable being assigned.  It must not
   *                       be {@code null}.
   * @param  valueArg      The argument to use as the value for the assignment.
   *                       It must not be {@code null}.
   */
  public static void generateVariableAssignment(
                          @NotNull final List<String> lineList,
                          final int indentSpaces,
                          @Nullable final String dataType,
                          @NotNull final String variableName,
                          @NotNull final ToCodeArgHelper valueArg)
  {
    final StringBuilder buffer = new StringBuilder();

    // Create a string that will be used for the initial indent.
    for (int i=0; i < indentSpaces; i++)
    {
      buffer.append(' ');
    }
    final String indent = buffer.toString();

    if (dataType != null)
    {
      buffer.append(dataType);
      buffer.append(' ');
    }

    buffer.append(variableName);
    buffer.append(" = ");

    boolean firstLine = true;
    final Iterator<String> valueLineIterator = valueArg.getLines().iterator();
    while (valueLineIterator.hasNext())
    {
      final String s = valueLineIterator.next();
      if (! firstLine)
      {
        buffer.setLength(0);
        buffer.append(indent);
      }

      buffer.append(s);
      if (! valueLineIterator.hasNext())
      {
        buffer.append(';');
      }

      if (firstLine)
      {
        firstLine = false;
        final String comment = valueArg.getComment();
        if (comment != null)
        {
          buffer.append(" // ");
          buffer.append(comment);
        }
      }

      lineList.add(buffer.toString());
    }
  }
}
