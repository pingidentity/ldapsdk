/*
 * Copyright 2010-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2025 Ping Identity Corporation
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
 * Copyright (C) 2010-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.controls;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;



/**
 * This enum defines the modes which may be used with the content
 * synchronization request control.  See the documentation for the
 * {@link ContentSyncRequestControl} class for more information about using the
 * content synchronization operation.
 */
public enum ContentSyncRequestMode
{
  /**
   * Indicates that the client only wishes to retrieve information about entries
   * which have changed up to this point.
   */
  REFRESH_ONLY(1),



  /**
   * Indicates that the client wishes to retrieve information about entries
   * which have changed up to this point, and also to be notified of any
   * additional matching changes in the future.
   */
  REFRESH_AND_PERSIST(3);



  // The integer value of this request mode.
  private final int intValue;



  /**
   * Creates a new content synchronization request mode with the specified
   * integer value.
   *
   * @param  intValue  The integer value for this request mode.
   */
  ContentSyncRequestMode(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves the integer value for this request mode.
   *
   * @return  The integer value for this request mode.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the content synchronization request mode with the specified
   * integer value.
   *
   * @param  intValue  The integer value for which to retrieve the corresponding
   *                   request mode.
   *
   * @return  The content synchronization mode with the specified integer value,
   *          or {@code null} if the given value does not correspond with any
   *          defined mode.
   */
  @Nullable()
  public static ContentSyncRequestMode valueOf(final int intValue)
  {
    if (intValue == REFRESH_ONLY.intValue())
    {
      return REFRESH_ONLY;
    }
    else if (intValue == REFRESH_AND_PERSIST.intValue())
    {
      return REFRESH_AND_PERSIST;
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves the content synchronization request mode with the specified name.
   *
   * @param  name  The name of the content synchronization request mode to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The requested content sync request mode, or {@code null} if no
   *          such mode is defined.
   */
  @Nullable()
  public static ContentSyncRequestMode forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "refreshonly":
      case "refresh-only":
      case "refresh_only":
        return REFRESH_ONLY;
      case "refreshandpersist":
      case "refresh-and-persist":
      case "refresh_and_persist":
        return REFRESH_AND_PERSIST;
      default:
        return null;
    }
  }
}
