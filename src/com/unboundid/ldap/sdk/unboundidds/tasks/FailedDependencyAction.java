/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tasks;



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class defines a failed dependency action, which controls how a task
 * should behave if any of its dependencies fails.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum FailedDependencyAction
{
  /**
   * The failed dependency action that indicates the dependent task should go
   * ahead and continue processing as if none of its dependencies had failed.
   */
  PROCESS("process"),



  /**
   * The failed dependency action that indicates the dependent task should be
   * canceled if any of its dependencies had failed.
   */
  CANCEL("cancel"),



  /**
   * The failed dependency action that indicates the dependent task should be
   * disabled if any of its dependencies had failed.
   */
  DISABLE("disable");



  // The name of this failed dependency action.
  private final String name;



  /**
   * Creates a new failed dependency action with the specified name.
   *
   * @param  name  The name of the failed dependency action to create.
   */
  FailedDependencyAction(final String name)
  {
    this.name = name;
  }



  /**
   * Retrieves the name of this failed dependency action.
   *
   * @return  The name of this failed dependency action.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the failed dependency action with the specified name.
   *
   * @param  name  The name of the failed dependency action to retrieve.
   *
   * @return  The requested failed dependency action, or {@code null} if there
   *          is no action with the given name.
   */
  public static FailedDependencyAction forName(final String name)
  {
    final String lowerName = toLowerCase(name);

    if (lowerName.equals("process"))
    {
      return PROCESS;
    }
    else if (lowerName.equals("cancel"))
    {
      return CANCEL;
    }
    else if (lowerName.equals("disable"))
    {
      return DISABLE;
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves a string representation of this failed dependency action.
   *
   * @return  A string representation of this failed dependency action.
   */
  @Override()
  public String toString()
  {
    return name;
  }
}
