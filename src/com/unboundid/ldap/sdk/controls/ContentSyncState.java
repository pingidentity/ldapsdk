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
package com.unboundid.ldap.sdk.controls;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;



/**
 * This enum defines the synchronization states for entries returned with the
 * content synchronization state control.  See the documentation for the
 * {@link ContentSyncRequestControl} class for more information about using the
 * content synchronization operation.
 */
public enum ContentSyncState
{
  /**
   * Indicates that the associated entry or reference was already present in
   * the server when the synchronization was initiated.
   */
  PRESENT(0),



  /**
   * Indicates that the associated entry or reference was just created by an
   * add or modify DN operation.
   */
  ADD(1),



  /**
   * Indicates that the associated entry or reference was just updated by a
   * modify or modify DN operation.
   */
  MODIFY(2),



  /**
   * Indicates that the associated entry or reference was just removed by a
   * delete or modify DN operation.
   */
  DELETE(3);



  // The integer value of this state.
  private final int intValue;



  /**
   * Creates a new content synchronization state with the specified integer
   * value.
   *
   * @param  intValue  The integer value for this request mode.
   */
  ContentSyncState(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves the integer value for this synchronization state.
   *
   * @return  The integer value for this synchronization state.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the content synchronization state with the specified integer
   * value.
   *
   * @param  intValue  The integer value for which to retrieve the corresponding
   *                   synchronization state.
   *
   * @return  The content synchronization state with the specified integer
   *          value, or {@code null} if the given value does not correspond with
   *          any defined state.
   */
  @Nullable()
  public static ContentSyncState valueOf(final int intValue)
  {
    if (intValue == PRESENT.intValue())
    {
      return PRESENT;
    }
    else if (intValue == ADD.intValue())
    {
      return ADD;
    }
    else if (intValue == MODIFY.intValue())
    {
      return MODIFY;
    }
    else if (intValue == DELETE.intValue())
    {
      return DELETE;
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves the content synchronization state with the specified name.
   *
   * @param  name  The name of the content synchronization state to retrieve.
   *               It must not be {@code null}.
   *
   * @return  The requested content synchronization state, or {@code null} if no
   *          such state is defined.
   */
  @Nullable()
  public static ContentSyncState forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "present":
        return PRESENT;
      case "add":
        return ADD;
      case "modify":
        return MODIFY;
      case "delete":
        return DELETE;
      default:
        return null;
    }
  }
}
