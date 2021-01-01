/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
 * This package contains a number of classes for interacting with ASN.1 BER
 * elements.  ASN.1 (Abstract Syntax Notation One) provides a framework for
 * representing typed data in a binary form, according to a set of encoding
 * rules.  This implementation uses the Basic Encoding Rules (BER), which is the
 * mechanism used to represent LDAP messages.  It does not provide all standard
 * types of ASN.1 elements, but includes those needed for LDAP processing,
 * including Boolean, enumerated, integer, null, octet string, sequence, and set
 * elements, as well as support for generic element types.  It also supports
 * element types that aren't used in LDAP directly, but may be used in related
 * areas, like generalized time and UTC time values.
 */
package com.unboundid.asn1;
