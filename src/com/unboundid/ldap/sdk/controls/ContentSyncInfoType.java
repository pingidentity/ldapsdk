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
  @Nullable()
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



  /**
   * Retrieves the content synchronization info type with the specified name.
   *
   * @param  name  The name of the content synchronization info type to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The requested content sync info type, or {@code null} if no such
   *          type is defined.
   */
  @Nullable()
  public static ContentSyncInfoType forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "newcookie":
      case "new-cookie":
      case "new_cookie":
        return NEW_COOKIE;
      case "refreshdelete":
      case "refresh-delete":
      case "refresh_delete":
        return REFRESH_DELETE;
      case "refreshpresent":
      case "refresh-present":
      case "refresh_present":
        return REFRESH_PRESENT;
      case "syncidset":
      case "sync-id-set":
      case "sync_id_set":
        return SYNC_ID_SET;
      default:
        return null;
    }
  }
}
