/*
 * Copyright 2008-2016 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2016 UnboundID Corp.
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
 * This package contains a number of helper classes for interacting with monitor
 * entries ing Ping Identity, UnboundID, and Alcatel-Lucent 8661 server
 * products.  It provides methods for parsing the monitor entries as specific
 * subtypes and for extracting the information that they provide in useful ways.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This package is part of the Commercial Edition of the
 *   UnboundID LDAP SDK for Java.  It is not available for use in applications
 *   that include only the Standard Edition of the LDAP SDK, and is not
 *   supported for use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * <BR>
 * The {@code MonitorManager} class provides a number of utility methods for
 * retrieving server monitor entries from a Ping identity/UnboundID Directory
 * Server.  The {@code MonitorEntry} class and its subclasses provide access to
 * the data in those monitor entries.
 */
package com.unboundid.ldap.sdk.unboundidds.monitors;
