/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the set of LDAP operation types.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum OperationType
{
  /**
   * The operation type that will be used for abandon operations.
   */
  ABANDON,



  /**
   * The operation type that will be used for add operations.
   */
  ADD,



  /**
   * The operation type that will be used for bind operations.
   */
  BIND,



  /**
   * The operation type that will be used for compare operations.
   */
  COMPARE,



  /**
   * The operation type that will be used for delete operations.
   */
  DELETE,



  /**
   * The operation type that will be used for extended operations.
   */
  EXTENDED,



  /**
   * The operation type that will be used for modify operations.
   */
  MODIFY,



  /**
   * The operation type that will be used for modify DN operations.
   */
  MODIFY_DN,



  /**
   * The operation type that will be used for search operations.
   */
  SEARCH,



  /**
   * The operation type that will be used for unbind operations.
   */
  UNBIND;



  /**
   * Retrieves the operation type with the specified name.
   *
   * @param  name  The name of the operation type to retrieve.  It must not be
   *               {@code null}.
   *
   * @return  The requested operation type, or {@code null} if no such operation
   *          type is defined.
   */
  @Nullable()
  public static OperationType forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "abandon":
        return ABANDON;
      case "add":
        return ADD;
      case "bind":
        return BIND;
      case "compare":
        return COMPARE;
      case "delete":
      case "del":
        return DELETE;
      case "extended":
      case "extendedoperation":
      case "extended-operation":
      case "extended_operation":
      case "extendedop":
      case "extended-op":
      case "extended_op":
      case "extop":
      case "ext-op":
      case "ext_op":
        return EXTENDED;
      case "modify":
      case "mod":
        return MODIFY;
      case "modifydn":
      case "modify-dn":
      case "modify_dn":
      case "moddn":
      case "mod-dn":
      case "mod_dn":
      case "modifyrdn":
      case "modify-rdn":
      case "modify_rdn":
      case "modrdn":
      case "mod-rdn":
      case "mod_rdn":
        return MODIFY_DN;
      case "search":
        return SEARCH;
      case "unbind":
        return UNBIND;
      default:
        return null;
    }
  }
}
