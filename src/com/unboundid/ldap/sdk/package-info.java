/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
 * This package contains classes which may be used to communicate with an LDAP
 * directory server.  The {@code LDAPConnection} and {@code LDAPConnectionPool}
 * classes provide the primary means for interacting with directory servers, and
 * both implement the {@code LDAPInterface} interface which can be used to allow
 * connections and connection pools to be used interchangeably for most types of
 * operations.  Other classes in this package provide data structures to assist
 * in LDAP communication.  Most request types are mutable, so that they can be
 * altered and re-used.
 */
package com.unboundid.ldap.sdk;
