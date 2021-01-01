/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
 * This package provides a number of classes that implement support for
 * interacting with JSON objects in the Ping Identity, UnboundID, or
 * Nokia/Alcatel-Lucent 8661 Directory Server.  This primarily includes JSON
 * object filters (which are an UnboundID-proprietary mechanism for performing
 * advanced matching on JSON object contents), but also contains other classes
 * in support for interacting with JSON in the Ping Identity, UnboundID, or
 * Nokia/Alcatel-Lucent 8661 Directory Server.
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
 * The Ping Identity, UnboundID, and Nokia/Alcatel-Lucent 8661 Directory Server
 * provides a "JSON Object" attribute syntax, which has an OID of
 * "1.3.6.1.4.1.30221.2.3.4", and can be used for attribute types whose values
 * are valid JSON objects.  This attribute type supports equality matching
 * (with the jsonObjectExactMatch matching rule as described below, but does not
 * support substring or ordering matching.  To create an attribute type
 * definition that uses the JSON object syntax, use a definition like the
 * following (but with the appropriate attribute type name and a non-example
 * OID):
 * <PRE>
 *   attributeTypes: ( 2.999.1.2.3.4
 *     NAME 'example-json-attribute'
 *     EQUALITY jsonObjectExactMatch
 *     SYNTAX 1.3.6.1.4.1.30221.2.3.4 )
 * </PRE>
 * <BR>
 * <H2>Matching with the jsonObjectExactMatch Matching Rule</H2>
 * The jsonObjectExactMatch matching rule (OID 1.3.6.1.4.1.30221.2.4.12) is an
 * equality matching rule that can be used to perform exact matching against
 * JSON objects.  It can be used in an equality search filter whose attribute
 * description names an attribute with a JSON object syntax and whose assertion
 * value is the string representation of a JSON object to match against values
 * of the specified attribute.  For example:
 * <BLOCKQUOTE>
 *   (jsonAttr={ "field1" : "value1", "field2":"value2" })
 * </BLOCKQUOTE>
 * <BR>
 * The jsonObjectExactMatch matching rule will also be used to perform matching
 * for a compare operation that targets attributes with a JSON object syntax,
 * and it will be used internally by the server to prevent an attribute with
 * that syntax from having duplicate values, and to identify which value is
 * targeted by a modification that attempts to delete a specific value.
 * <BR><BR>
 * The constraints that the jsonObjectExactMatch matching rule will use when
 * determining whether two JSON objects are equal are:
 * <UL>
 *   <LI>The names of the fields in each object must be identical, although the
 *       order in which the fields appear in the string representation is not
 *       significant.  Neither object will be permitted to have a field that is
 *       not present in the other object.  Field names will be treated in a
 *       case-sensitive manner (e.g., a field named "x" will be considered
 *       different from a field named "X").</LI>
 *   <LI>The values of fields with the same name must be of the same data type.
 *       For example, the string "true" will not match the Boolean {@code true},
 *       the string "1234" will not match the number 1234, and the string "null"
 *       will not match the {@code null} value.  Similarly, a single non-array
 *       value will not match an array, even if the array contains only that
 *       value (e.g., so a value of "a" will not match ["a"]).</LI>
 *   <LI>The values of fields with the same name must be logically equivalent.
 *       Logical equivalence is defined as follows for each data type:
 *       <UL>
 *         <LI>{@code null} will only match {@code null}.</LI>
 *         <LI>{@code true} will only match {@code true}.</LI>
 *         <LI>{@code false} will only match {@code false}.</LI>
 *         <LI>Strings will be compared in a case-insensitive manner, but all
 *             spaces will be considered significant.  This will use logic
 *             equivalent to the {@code String.equalsIgnoreCase} method.</LI>
 *         <LI>Numbers will only match other numbers with equivalent numeric
 *             values, even if they are expressed with different string
 *             representations.  For example, the number 12345 will match the
 *             number 12345.0 and the number 1.2345e4.  Floating-point numbers
 *             with nonzero fractional components will not match integer numbers
 *             without fractional components (e.g., 12345 will not match
 *             12345.1).</LI>
 *         <LI>Arrays will only match arrays containing logically-equivalent
 *             values in the same order.</LI>
 *         <LI>JSON objects that appear as field values or inside arrays will
 *             use the logic presented here.</LI>
 *       </UL>
 *   </LI>
 * </UL>
 * <BR>
 * The matching performed by the jsonObjectExactMatch matching rule is
 * equivalent to that performed by the multi-argument {@code JSONObject.equals}
 * method with {@code ignoreFieldNameCase=false}, {@code ignoreValueCase=true},
 * and {@code ignoreArrayOrder=false}.
 * <BR>
 * <H2>Matching with the jsonObjectFilterExtensibleMatch Matching Rule</H2>
 * The jsonObjectFilterExtensibleMatch matching rule (OID
 * 1.3.6.1.4.1.30221.2.4.13) provides a much greater degree of flexibility for
 * performing matching against JSON objects than the jsonObjectExactMatch
 * matching rule, but it is only expected to be used in LDAP filters that
 * perform extensible matching (<B>NOTE</B>:  do not attempt to use the
 * jsonObjectFilterExtensibleMatch matching rule as the default equality
 * matching rule for attribute types).  In such filters, the filter should
 * include an attribute description that names an attribute with the JSON object
 * syntax, a matching rule ID of jsonObjectFilterExtensibleMatch (or the numeric
 * OID 1.3.6.1.4.1.30221.2.4.13), and an assertion value that is a JSON object
 * that defines the constraints for identifying which JSON objects to match.
 * For example:
 * <BLOCKQUOTE>
 *   (jsonAttr:jsonObjectFilterExtensibleMatch:={ "filterType":"fieldEquals",
 *        "fieldName":"field1", "fieldValue":"value1" })
 * </BLOCKQUOTE>
 * <BR>
 * All JSON object filters must include a field named "filterType" that
 * indicates the type of matching to be performed.  The other fields that are
 * required to be present, or that may optionally be present, vary based on the
 * specified filter type.  See the class-level documentation for each of the
 * {@link com.unboundid.ldap.sdk.unboundidds.jsonfilter.JSONObjectFilter}
 * subclasses for detailed information about the type of matching performed by
 * that type of filter, as well as the sets of required and optional fields for
 * that filter type.
 */
package com.unboundid.ldap.sdk.unboundidds.jsonfilter;
