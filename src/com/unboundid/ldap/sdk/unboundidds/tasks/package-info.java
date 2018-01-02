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



/**
 * This package contains a number of helper classes for invoking and interacting
 * with scheduled tasks in Ping Identity, UnboundID, and Alcatel-Lucent 8661
 * server products.  Tasks may be used to perform various kinds of
 * administrative functions, like backing up and restoring backends, importing
 * and exporting data, rebuilding indexes, and shutting down or restarting the
 * server.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  The classes within this package, and elsewhere within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The {@code TaskManager} class provides a number of utility methods for
 * interacting with tasks in a Ping Identity, UnboundID, or Alcatel-Lucent 8661
 * Directory Server.  The {@code Task} class and its subclasses provide a
 * framework for accessing the generic and task-specific information associated
 * with tasks.
 */
package com.unboundid.ldap.sdk.unboundidds.tasks;
