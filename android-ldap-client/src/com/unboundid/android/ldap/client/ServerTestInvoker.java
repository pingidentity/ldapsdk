/*
 * Copyright 2009-2016 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2016 UnboundID Corp.
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
package com.unboundid.android.ldap.client;



import java.util.LinkedList;



/**
 * This interface defines a set of methods that should be implemented by a class
 * which can test the validity of a configured server.
 */
interface ServerTestInvoker
          extends StringProvider
{
  /**
   * Indicates that the server test has completed.
   *
   * @param  acceptable  Indicates that the instance appears to be acceptable.
   * @param  reasons     Reasons that the instance was not acceptable.
   */
  void testCompleted(final boolean acceptable,
                     final LinkedList<String> reasons);
}
