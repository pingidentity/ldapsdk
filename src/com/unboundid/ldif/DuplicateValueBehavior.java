/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.ldif;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines a set of possible behaviors that may be exhibited by the
 * LDIF reader when encountering entries with duplicate attribute values.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum DuplicateValueBehavior
{
  /**
   * Indicates that duplicate values should be stripped, so that the resulting
   * entry will have only one copy of the value.
   */
  STRIP,



  /**
   * Indicates that duplicate values should be retained, so that the resulting
   * entry may have multiple copies of the value.  This is illegal and may cause
   * significant problems with attempts to use the resulting entry.
   */
  RETAIN,



  /**
   * Indicates that any entry containing duplicate attribute values should be
   * rejected.
   */
  REJECT;



  /**
   * Retrieves the duplicate value behavior with the specified name.
   *
   * @param  name  The name of the duplicate value behavior to retrieve.  It
   *               must not be {@code null}.
   *
   * @return  The requested duplicate value behavior, or {@code null} if no such
   *          behavior is defined.
   */
  @Nullable()
  public static DuplicateValueBehavior forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "strip":
        return STRIP;
      case "retain":
        return RETAIN;
      case "reject":
        return REJECT;
      default:
        return null;
    }
  }
}
