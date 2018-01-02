/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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



/**
 * This interface defines a set of methods that should be implemented by any
 * class which has the ability to retrieve the string for a given identifier.
 */
interface StringProvider
{
  /**
   * Retrieves the string for the given identifier.
   *
   * @param  id  The identifier for the string to retrieve.  It must be one of
   *             the identifiers in the {@link R.string} class.
   *
   * @return  The string for the given identifier.
   */
  String getString(int id);



  /**
   * Retrieves the string for the given identifier.
   *
   * @param  id    The identifier for the string to retrieve.  It must be one of
   *               the identifiers in the {@link R.string} class.
   * @param  args  The objects to use as arguments to include the string.
   *
   * @return  The string for the given identifier.
   */
  String getString(int id, Object... args);
}
