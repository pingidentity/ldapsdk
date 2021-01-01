/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
 * with scheduled tasks in Ping Identity, UnboundID, and Nokia/Alcatel-Lucent
 * 8661 server products.  Tasks may be used to perform various kinds of
 * administrative functions, like backing up and restoring backends, importing
 * and exporting data, rebuilding indexes, and shutting down or restarting the
 * server.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  The classes within this package, and elsewhere within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The {@code TaskManager} class provides a number of utility methods for
 * interacting with tasks in a Ping Identity, UnboundID, or Nokia/Alcatel-Lucent
 * 8661 Directory Server.  The {@code Task} class and its subclasses provide a
 * framework for accessing the generic and task-specific information associated
 * with tasks.
 */
package com.unboundid.ldap.sdk.unboundidds.tasks;
