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
public enum ContentSyncInfoType
{
  /**
   * Indicates that the associated content synchronization info response only
   * provides a new state cookie.
   */
  NEW_COOKIE((byte) 0x80),



  /**
   * Indicates that the associated content synchronization info response is used
   * to indicate that a delete phase has ended.
   */
  REFRESH_DELETE((byte) 0xA1),



  /**
   * Indicates that the associated content synchronization info response is used
   * to indicate that a present phase has ended.
   */
  REFRESH_PRESENT((byte) 0xA2),



  /**
   * Indicates that the associated content synchronization info response is used
   * to provide information about multiple entries which have been deleted or
   * multiple entries which have remained unchanged.
   */
  SYNC_ID_SET((byte) 0xA3);



  // The BER type used for this sync info type in the value of a content
  // synchronization info message.
  private final byte type;



  /**
   * Creates a new content synchronization info type value with the specified
   * BER type.
   *
   * @param  type  The BER type used for this sync info type in the value of a
   *               content synchronization info message.
   */
  ContentSyncInfoType(final byte type)
  {
    this.type = type;
  }



  /**
   * Retrieves the BER type for this synchronization info type value.
   *
   * @return  The BER type for this synchronization info type value.
   */
  public byte getType()
  {
    return type;
  }



  /**
   * Retrieves the content synchronization info type with the specified BER
   * type.
   *
   * @param  type  The BER type of the content synchronization info type value
   *               to retrieve.
   *
   * @return  The content synchronization info value with the specified BER
   *          type, or {@code null} if the given value does not correspond with
   *          any defined type.
   */
  public static ContentSyncInfoType valueOf(final byte type)
  {
    if (type == NEW_COOKIE.getType())
    {
      return NEW_COOKIE;
    }
    else if (type == REFRESH_DELETE.getType())
    {
      return REFRESH_DELETE;
    }
    else if (type == REFRESH_PRESENT.getType())
    {
      return REFRESH_PRESENT;
    }
    else if (type == SYNC_ID_SET.getType())
    {
      return SYNC_ID_SET;
    }
    else
    {
      return null;
    }
  }
}
