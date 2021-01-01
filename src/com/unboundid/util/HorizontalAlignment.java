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



/**
 * This enumeration defines a set of values that may indicate how text should be
 * horizontally aligned.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum HorizontalAlignment
{
  /**
   * Indicates that items should be aligned along their left edges.
   */
  LEFT(),



  /**
   * Indicates that text should be aligned along their centers.
   */
  CENTER(),



  /**
   * Indicates that text should be aligned along right edges.
   */
  RIGHT();



  /**
   * Appends the provided string to the given buffer, aligned properly within
   * the specified width.  Spaces will be inserted before and/or after the text
   * as necessary to achieve the desired alignment.  This method will always
   * append exactly {@code width} characters (including spaces added to achieve
   * the desired alignment) to the provided buffer.  If the given text is longer
   * than {@code width}, then only the first {@code width} characters of the
   * provided text will be appended.
   *
   * @param  buffer  The buffer to which the formatted text should be appended.
   *                 It must not be {@code null}.
   * @param  text    The text to be added to the provided buffer, with
   *                 additional spaces as necessary to achieve the desired
   *                 width.  It must not be {@code null}.
   * @param  width   The number of characters to append to the provided buffer.
   *                 It must be greater than or equal to 1.
   */
  public void format(@NotNull final StringBuilder buffer,
                     @NotNull final String text, final int width)
  {
    final int length = text.length();
    if (length >= width)
    {
      buffer.append(text.substring(0, width));
      return;
    }

    final int spacesBefore;
    final int spacesAfter;
    switch (this)
    {
      case LEFT:
        spacesBefore = 0;
        spacesAfter  = width - length;
        break;
      case CENTER:
        final int totalSpaces = width - length;
        spacesBefore = totalSpaces / 2;
        spacesAfter  = totalSpaces - spacesBefore;
        break;
      case RIGHT:
      default:
        spacesBefore = width - length;
        spacesAfter  = 0;
        break;
    }

    for (int i=0; i < spacesBefore; i++)
    {
      buffer.append(' ');
    }

    buffer.append(text);

    for (int i=0; i < spacesAfter; i++)
    {
      buffer.append(' ');
    }
  }



  /**
   * Retrieves the horizontal alignment value with the specified name.
   *
   * @param  name  The name of the horizontal alignment value to retrieve.  It
   *               must not be {@code null}.
   *
   * @return  The requested horizontal alignment value, or {@code null} if no
   *          such value is defined.
   */
  @Nullable()
  public static HorizontalAlignment forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "left":
        return LEFT;
      case "center":
        return CENTER;
      case "right":
        return RIGHT;
      default:
        return null;
    }
  }
}
