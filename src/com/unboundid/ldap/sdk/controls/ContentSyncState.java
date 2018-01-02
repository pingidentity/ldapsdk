/*
 * Copyright 2010-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2018 Ping Identity Corporation
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
}
