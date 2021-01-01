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
package com.unboundid.util.json;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;

import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.ServerSet;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.json.JSONMessages.*;



/**
 * This class provides a utility that may be used to obtain information that may
 * be used to create LDAP connections to one or more servers from a definition
 * contained in a JSON object.  This makes it easier to create applications that
 * provide the information necessary for creating LDAP connections and
 * connection pools in a JSON-formatted configuration file.
 * <BR><BR>
 * The JSON-based specification is organized into five sections:
 * <OL>
 *   <LI>
 *     A "server-details" section that provides information about the directory
 *     server(s) to access.  The specification supports accessing a single
 *     server, as well as a number of schemes for establishing connections
 *     across multiple servers.
 *   </LI>
 *   <LI>
 *     A "communication-security" section that provides information that may be
 *     used to secure communication using SSL or StartTLS.
 *   </LI>
 *   <LI>
 *     A "connection-options" section that can be used customize a number of
 *     connection-related options, like connect and response timeouts, whether
 *     to follow referrals, whether to retrieve schema from the backend server
 *     for client-side use, and whether to use synchronous mode for more
 *     efficient communication if connections will not be used in an
 *     asynchronous manner.
 *   </LI>
 *   <LI>
 *     An "authentication-details" section that provides information for
 *     authenticating connections using a number of mechanisms.
 *   </LI>
 *   <LI>
 *     A "connection-pool-options" section that provides information to use to
 *     customize the behavior to use for connection pools created from this
 *     specification.
 *   </LI>
 * </OL>
 * Each of these sections will be described in more detail below.
 * <BR><BR>
 * <H2>The "server-details" Section</H2>
 * The JSON object that comprises the LDAP connection details specification must
 * have a top-level "server-details" field whose value is a JSON object that
 * provides information about the server(s) to which connections may be
 * established.  The value of the "server-details" field must itself be a JSON
 * object, and that object must have exactly one field, which depends on the
 * mechanism that the LDAP SDK should use to select the target directory
 * servers.
 * <BR><BR>
 * <B>The "server-details" Section for Connecting to a Single Server</B>
 * <BR>
 * When establishing a connection to a single server, the "server-details"
 * value should be a JSON object that contains a "single-server" field whose
 * value is a JSON object with "address" and "port" fields.  For example, the
 * following is a valid specification that may be used to establish connections
 * to the server at ldap.example.com on port 389:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "single-server":
 *       {
 *         "address":"ldap.example.com",
 *         "port":389
 *       }
 *     }
 *   }
 * </PRE>
 * <BR>
 * <B>The "server-details" Section for Selecting from a Set of Servers in a
 * Round-Robin Manner</B>
 * <BR>
 * If you have a set of servers that you want to connect to in a round-robin
 * manner (in which the LDAP SDK will maintain a circular list of servers and
 * each new connection will go to the next server in the list), the
 * "server-details" value should be a JSON object that contains a
 * "round-robin-set" field whose value is a JSON object that contains a "server"
 * field with an array of JSON objects, each of which contains "address" and
 * "port" fields for a target server.  For example, the following is a valid
 * specification that may be used to establish connections across the servers
 * ldap1.example.com, ldap2.example.com, and ldap3.example.com, all on port 389:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "round-robin-set":
 *       {
 *         "servers":
 *         [
 *           {
 *             "address":"ldap1.example.com",
 *             "port":389
 *           },
 *           {
 *             "address":"ldap2.example.com",
 *             "port":389
 *           },
 *           {
 *             "address":"ldap2.example.com",
 *             "port":389
 *           }
 *         ]
 *       }
 *     }
 *   }
 * </PRE>
 * <BR>
 * <B>The "server-details" Section for Selecting from a Set of Servers in a
 * Fewest Connections Manner</B>
 * <BR>
 * If you have a set of servers that you want to connect to in a manner that
 * selects the server with the fewest established connections (at least
 * connections created from this specification), the "server-details" value
 * should be a JSON object that contains a "fewest-connections-set" field whose
 * value is a JSON object that contains a "server" field with an array of JSON
 * objects, each of which contains "address" and "port" fields for a target
 * server.  For example, the following is a valid specification that may be used
 * to establish connections across the servers ldap1.example.com,
 * ldap2.example.com, and ldap3.example.com, all on port 389:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "fewest-connections-set":
 *       {
 *         "servers":
 *         [
 *           {
 *             "address":"ldap1.example.com",
 *             "port":389
 *           },
 *           {
 *             "address":"ldap2.example.com",
 *             "port":389
 *           },
 *           {
 *             "address":"ldap2.example.com",
 *             "port":389
 *           }
 *         ]
 *       }
 *     }
 *   }
 * </PRE>
 * <BR>
 * <B>The "server-details" Section for Selecting from a Set of Servers in a
 * Fastest Connect Manner</B>
 * <BR>
 * If you have a set of servers that you want to connect to in a manner that
 * attempts to minimize the time required to establish new connections (by
 * simultaneously attempting to create connections to every server in the set
 * and taking the first connection to be established), the "server-details"
 * value should be a JSON object that contains a "fastest-connect-set" field
 * whose value is a JSON object that contains a "server" field with an array of
 * JSON objects, each of which contains "address" and "port" fields for a target
 * server.  For example, the following is a valid specification that may be used
 * to establish connections across the servers ldap1.example.com,
 * ldap2.example.com, and ldap3.example.com, all on port 389:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "fastest-connect-set":
 *       {
 *         "servers":
 *         [
 *           {
 *             "address":"ldap1.example.com",
 *             "port":389
 *           },
 *           {
 *             "address":"ldap2.example.com",
 *             "port":389
 *           },
 *           {
 *             "address":"ldap2.example.com",
 *             "port":389
 *           }
 *         ]
 *       }
 *     }
 *   }
 * </PRE>
 * <BR>
 * <B>The "server-details" Section for Selecting from a Set of Servers in a
 * Failover Manner</B>
 * <BR>
 * If you have a set of servers that you want to connect to in a manner that
 * attempts to consistently establish connections to the same server (as long as
 * it is available, and use a consistent failover order if the preferred server
 * isn't available), the "server-details" value should be a JSON object that
 * contains a "failover-set" field whose value is a JSON object that contains a
 * "failover-order" field that provides a list of the details to use in order
 * to establish the connections.  For example, the following is a valid
 * specification that may be used to always try to establish connections to
 * ldap1.example.com:389, then try ldap2.example.com:389, and then try
 * ldap3.example.com:389:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "failover-set":
 *       {
 *         "failover-order":
 *         [
 *           {
 *             "single-server":
 *             {
 *               "address":"ldap1.example.com",
 *               "port":389
 *             }
 *           },
 *           {
 *             "single-server":
 *             {
 *               "address":"ldap2.example.com",
 *               "port":389
 *             }
 *           },
 *           {
 *             "single-server":
 *             {
 *               "address":"ldap2.example.com",
 *               "port":389
 *             }
 *           }
 *         ]
 *       }
 *     }
 *   }
 * </PRE>
 * The failover set actually has the ability to perform failover across any kind
 * of set.  This is a powerful capability that can be useful to define a
 * hierarchy of sets, for example for sets referring to servers in different
 * data centers (e.g., to prefer connecting to one of the servers in the local
 * data center over servers in a remote data center).  For example, the
 * following is a valid specification that may be used to connect to the server
 * with the fewest connections in the east data center, but if no east servers
 * are available then it will fail over to select the server with the fewest
 * connections in the west data center:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "failover-set":
 *       {
 *         "failover-order":
 *         [
 *           {
 *             "fewest-connections-set":
 *             {
 *               "servers":
 *               [
 *                 {
 *                   "address":"ldap1.east.example.com",
 *                   "port":389
 *                 },
 *                 {
 *                   "address":"ldap2.east.example.com",
 *                   "port":389
 *                 }
 *               ]
 *             }
 *           },
 *           {
 *             "fewest-connections-set":
 *             {
 *               "servers":
 *               [
 *                 {
 *                   "address":"ldap1.west.example.com",
 *                   "port":389
 *                 },
 *                 {
 *                   "address":"ldap2.west.example.com",
 *                   "port":389
 *                 }
 *               ]
 *             }
 *           }
 *         ]
 *       }
 *     }
 *   }
 * </PRE>
 * For connections that are part of a connection pool, failover sets have the
 * ability to assign a different maximum connection age to connections created
 * to a non-preferred server.  This can help allow failover connections to be
 * migrated back to the preferred server more quickly once that server is
 * available again.  If you wish to specify an alternate maximum connection age
 * for connections to a non-preferred server, you may include the
 * "maximum-failover-connection-age-millis" field in the "failover-set" object.
 * The value of this field should be a number that is greater than zero to
 * specify the maximum age (in milliseconds) for those connections, or a value
 * of zero to indicate that they should not be subject to a maximum age.  If
 * this field is not present, then these connections will be assigned the
 * default maximum connection age configured for the pool.
 * <BR><BR>
 * <H2>The "communication-security" Section</H2>
 * This section may be used to provide information about the type of security to
 * use to protect communication with directory servers.  If the specification
 * includes information about multiple servers, then all servers will use the
 * same type of security.
 * <BR><BR>
 * If present, the "communication-security" field should have a value that is a
 * JSON object.  This object must have a "security-type" field with one of the
 * following values:
 * <UL>
 *   <LI>
 *     "none" -- Indicates that no communication security should be used.  The
 *     communication will not be encrypted.
 *   </LI>
 *   <LI>
 *     "SSL" -- Indicates that all communication should be encrypted with the
 *     SSL (secure sockets layer) protocol, or more likely its more secure
 *     successor TLS (transport-layer security) protocol.  You can also specify
 *     a value of "TLS" to use this type of security.
 *   </LI>
 *   <LI>
 *     "StartTLS" -- Indicates that the connection will be initially established
 *     in a non-secure manner, but will be immediately secured with the StartTLS
 *     extended operation.
 *   </LI>
 * </UL>
 * If you do not wish to use any form of communication security, then the
 * "security-type" field is the only one that should be present.  For example,
 * the following is a valid specification that will use unencrypted
 * communication to the server ldap.example.com on port 389:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "single-server":
 *       {
 *         "address":"ldap.example.com",
 *         "port":389
 *       }
 *     },
 *     "communication-security":
 *     {
 *       "security-type":"none"
 *     }
 *   }
 * </PRE>
 * <BR>
 * If you wish to secure the communication with either SSL or StartTLS, then
 * there are a number of other options that may be specified using fields in the
 * "communication-security" object.  Those options fall into two basic
 * categories:  fields that provide information about how the client should
 * determine whether to trust the certificate presented by the server, and
 * fields that provide information about whether the client should present its
 * own certificate to the server.  The fields related to client trust include:
 * <UL>
 *   <LI>
 *     "trust-all-certificates" -- Indicates whether the client should blindly
 *     trust any certificate that the server presents to it.  Using blind trust
 *     is convenient for testing and troubleshooting purposes, but is not
 *     recommended for production use because it can leave the communication
 *     susceptible to man-in-the-middle attacks.  If this field is present, then
 *     it should have a boolean value.  If it is not present, a default value
 *     of {@code false} will be assumed.  If it is present with a value of
 *     {@code true}, then the "use-jvm-default-trust-store", "trust-store-file",
 *     "trust-store-type", "trust-store-pin", and "trust-store-pin-file" fields
 *     should not be used.
 *   </LI>
 *   <LI>
 *     "use-jvm-default-trust-store" -- Indicates that certificates signed by an
 *     authority listed in the JVM's default set of trusted issuers should be
 *     trusted.  If this field is present, it should have a boolean value.  The
 *     JVM-default trust store may be used on its own or in conjunction with a
 *     trust store file.
 *   </LI>
 *   <LI>
 *     "trust-store-file" -- Specifies the path to a trust store file (in JKS
 *     or PKCS#12 format).  If this is present, then the presented certificate
 *     will only be trusted if the trust store file contains information about
 *     all of the issuers in the certificate chain.
 *   </LI>
 *   <LI>
 *     "trust-store-type"  -- Indicates the format for the trust store file.
 *     If this is present, then its value should be a string that is either
 *     "JKS" or "PKCS12".  If it is not present, then a default trust store type
 *     of "JKS" will be assumed.
 *   </LI>
 *   <LI>
 *     "trust-store-pin" -- Specifies the PIN that should be used to access the
 *     contents of the trust store.  If this field is present, then its value
 *     should be a string that is the clear-text PIN.  If it is not present,
 *     then the PIN may be read from a file specified using the
 *     "trust-store-pin-file" field.  If neither the "trust-store-pin" field nor
 *     the "trust-store-pin-file" field is present, then no PIN will be used
 *     when attempting to access the trust store (and in many cases, no trust
 *     store PIN will be required).
 *   </LI>
 *   <LI>
 *     "trust-store-pin-file" -- Specifies the path to a file that contains the
 *     PIN to use to access the contents of the trust store.  If this field is
 *     present, then its value must be the path to a file containing a single
 *     line, which is the clear-text PIN.  If it is not present, then the PIN
 *     may be obtained from the "trust-store-pin" field.  If neither the
 *     "trust-store-pin" field nor the "trust-store-pin-file" field is present,
 *     then no PIN will be used when attempting to access the trust store (and
 *     in many cases, no trust store PIN will be required).
 *   </LI>
 *   <LI>
 *     "trust-expired-certificates" -- Indicates whether the client should
 *     trust certificates that are not yet valid or that have expired.  If this
 *     field is present, then its value must be a boolean.  If the value is
 *     {@code true}, then the certificate validity dates will not be taken into
 *     consideration when deciding whether to trust a certificate.  If the value
 *     is {@code false}, then any certificate whose validity window does not
 *     include the current time will not be trusted (even if
 *     "trust-all-certificates" is {@code true}).  If this field is not present,
 *     then a default of {@code false} will be assumed.
 *   </LI>
 *   <LI>
 *     "verify-address-in-certificate" -- Indicates whether the client should
 *     examine the information contained in the certificate to verify that the
 *     address the client used to connect to the server matches address
 *     information contained in the certificate (whether in the CN attribute of
 *     the certificate's subject, or in a subjectAltName extension of type
 *     dNSName, uniformResourceIdentifier, or iPAddress).  If this field is
 *     present, then its value must be a boolean.  If it is absent, then a
 *     default value of {@code false} will be assumed.
 *   </LI>
 * </UL>
 * If none of the above fields are provided, then the JVM's default trust
 * mechanism will be used.  This will generally only trust certificates signed
 * by a well-known certification authority.
 * <BR><BR>
 * The fields related to presenting a client certificate include:
 * <UL>
 *   <LI>
 *     "key-store-file" -- Specifies the path to a key store file (in JKS or
 *     PKCS#12 format) that contains the certificate that the client should
 *     present to the server.  If this is present, then the value must be a
 *     string that is the path to the key store file.  If it is not present,
 *     then no key store file will be used.
 *   </LI>
 *   <LI>
 *     "key-store-type" -- Specifies the type of key store that should be used.
 *     If this is present, then its value must be a string, and that string
 *     should be "JKS" or "PKCS12" (if a "key-store-file" value is present), or
 *     "PKCS11" (if the client certificate is contained in a security module
 *     accessible via the PKCS#11 API.  If this field is not present but a
 *     "key-store-file" value is provided, then a default value of "JKS" will be
 *     assumed.
 *   </LI>
 *   <LI>
 *     "key-store-pin" -- Specifies the PIN that should be used to access the
 *     contents of the key store.  If this field is present, then its value
 *     should be a string that is the clear-text PIN.  If it is not present,
 *     then the PIN may be read from a file specified using the
 *     "key-store-pin-file" field.  If neither the "key-store-pin" field nor the
 *     "key-store-pin-file" field is present, then no PIN will be used when
 *     attempting to access the key store (although key stores generally require
 *     a PIN in order to access private key information).
 *   </LI>
 *   <LI>
 *     "key-store-pin-file" -- Specifies the path to a file containing the PIN
 *     that should be used to access the contents of the key store.  If this
 *     field is present, then its value should be the path to a file containing
 *     the clear-text PIN.  If it is not present, then the PIN may be obtained
 *     from the "key-store-pin" field.  If neither the "key-store-pin" field nor
 *     the "key-store-pin-file" field is present, then no PIN will be used when
 *     attempting to access the key store (although key stores generally require
 *     a PIN in order to access private key information).
 *   </LI>
 *   <LI>
 *     "client-certificate-alias" -- Specifies the alias (also known as the
 *     nickname) of the client certificate that should be presented to the
 *     directory server.  If this field is present, then its value should be a
 *     string that is the alias for a valid certificate that exists in the
 *     key store.  If this field is not present, then the JVM will automatically
 *     attempt to select a suitable client certificate.
 *   </LI>
 * </UL>
 * If none of the above fields are provided, then the client will not attempt to
 * present a certificate to the server.
 * <BR><BR>
 * The following example demonstrates a simple specification that can be used to
 * establish SSL-based connections to a single server.  The client will trust
 * any certificates signed by one of the JVM's default issuers, or any
 * certificate contained in or signed by a certificate contained in the
 * specified trust store file.  As no key store is provided, the client will not
 * attempt to present its own certificate to the server.
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "single-server":
 *       {
 *         "address":"ldap.example.com",
 *         "port":636
 *       }
 *     },
 *     "communication-security":
 *     {
 *       "security-type":"SSL",
 *       "use-jvm-default-trust-store":true,
 *       "trust-store-file":"/path/to/trust-store.jks",
 *       "trust-store-type":"JKS",
 *       "verify-address-in-certificate":true
 *     }
 *   }
 * </PRE>
 * <BR>
 * The "communication-security" field is optional, and if it is omitted from the
 * specification then it will be equivalent to including it with a
 * "security-type" value of "none".
 * <BR><BR>
 * <H2>The "connection-options" Section</H2>
 * The "connection-options" section may be used to provide information about a
 * number of settings that may be used in the course of establishing a
 * connection, or that may affect the behavior of the connection.  The value
 * of the "connection-options" field must be a JSON object, and the following
 * fields may appear in that object:
 * <UL>
 *   <LI>
 *     "connect-timeout-millis" -- Specifies the maximum length of time (in
 *     milliseconds) that a connection attempt may block while waiting for the
 *     connection to be established.  If this field is present, then its value
 *     must be a positive integer to specify the timeout, or a value of zero to
 *     indicate that no timeout should be enforced by the LDAP SDK.  Note that
 *     the underlying operating system may enforce its own connect timeout, and
 *     if that value is smaller than the LDAP SDK timeout then the operating
 *     system's timeout value will be used.  If this field is not present, then
 *     a default of 60000 (1 minute) will be used.
 *   </LI>
 *   <LI>
 *     "default-response-timeout-millis" -- Specifies the default timeout (in
 *     milliseconds) that will be used when waiting for a response to a request
 *     sent to the server.  If this field is present, then its value must be a
 *     positive integer to specify the timeout, or a value of zero to indicate
 *     that no timeout should be enforced.  If this field is not present, then a
 *     default of 300000 (5 minutes) will be used.  Note that this default
 *     response timeout can be overridden on a per-request basis using the
 *     {@code setResponseTimeoutMillis} method provided by the request object.
 *   </LI>
 *   <LI>
 *     "follow-referrals" -- Indicates whether the LDAP SDK should automatically
 *     attempt to follow any referrals that are returned during processing.  If
 *     this field is present, the value should be a boolean.  If it is absent,
 *     then a default  of {@code false} will be assumed.
 *   </LI>
 *   <LI>
 *     "use-schema" -- Indicates whether the LDAP SDK should attempt to retrieve
 *     schema information from the directory server upon establishing a
 *     connection to that server, and should then use that schema information
 *     for more accurate client-side matching operations.  If present, this
 *     field should have a boolean value.  If it is not present, then a default
 *     value of {@code false} will be used.
 *   </LI>
 *   <LI>
 *     "use-synchronous-mode" -- Indicates whether connections should be created
 *     in synchronous mode, which may be more efficient and less resource
 *     intensive than connections not created in synchronous mode, but may only
 *     be used if no attempt will be made to issue asynchronous requests over
 *     the connection, or to attempt to use the connection simultaneously by
 *     multiple threads.  If this field is present, then its value must be a
 *     boolean.  If it is not present, then a default value of {@code false}
 *     will be used.
 *   </LI>
 * </UL>
 * <BR>
 * The "connection-options" field is optional, and if it is omitted from the
 * specification then the default values will be used for all options.
 * <BR><BR>
 * <H2>The "authentication-details" Section</H2>
 * The "authentication-details" section may be used to provide information for
 * authenticating the connections that are created.  The value of the
 * "authentication-details" field must be a JSON object, and it must include an
 * "authentication-type" field to specify the mechanism to use to authenticate.
 * The selected authentication type dictates the other fields that may be
 * present in the object.
 * <BR><BR>
 * <B>The "none" Authentication Type</B>
 * <BR>
 * If no authentication should be performed, then the "authentication-type"
 * value should be "none".  No other fields should be specified in the
 * "authentication-details".  For example:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "single-server":
 *       {
 *         "address":"ldap.example.com",
 *         "port":389
 *       }
 *     },
 *     "authentication-details":
 *     {
 *       "authentication-type":"none"
 *     }
 *   }
 * </PRE>
 * <BR>
 * <B>The "simple" Authentication Type</B>
 * <BR>
 * If you wish to authenticate connections with an LDAP simple bind, then you
 * can specify an "authentication-type" value of "simple".  The following
 * additional fields may be included in the "authentication-details" object for
 * this authentication type:
 * <UL>
 *   <LI>
 *     "dn" -- The DN to use to bind to the server.  This field must be present,
 *     and its value must be a string containing the bind DN, or an empty string
 *     to indicate anonymous simple authentication.
 *   </LI>
 *   <LI>
 *     "password" -- The password to use to bind to the server.  If this field
 *     is present, then its value must be a string that contains the clear-text
 *     password, or an empty string to indicate anonymous simple
 *     authentication.  If it is not provided, then the "password-file" field
 *     must be used to specify the path to a file containing the bind password.
 *   </LI>
 *   <LI>
 *     "password-file" -- The path to a file containing the password to use to
 *     bind to the server.  If this field is present, then its value must be a
 *     string that represents the path to a file containing a single line that
 *     contains the clear-text password.  If it is not provided, then the
 *     "password" field must be used to specify the password.
 *   </LI>
 * </UL>
 * For example:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "single-server":
 *       {
 *         "address":"ldap.example.com",
 *         "port":389
 *       }
 *     },
 *     "authentication-details":
 *     {
 *       "authentication-type":"simple",
 *       "dn":"uid=john.doe,ou=People,dc=example,dc=com",
 *       "password-file":"/path/to/password.txt"
 *     }
 *   }
 * </PRE>
 * <BR>
 * <B>The "CRAM-MD5" Authentication Type</B>
 * If you wish to authenticate connections with the CRAM-MD5 SASL mechanism,
 * then you can specify an "authentication-type" value of "CRAM-MD5".  The
 * following additional fields may be included in the "authentication-details"
 * object for this authentication type:
 * <UL>
 *   <LI>
 *     "authentication-id" -- The authentication ID to use to bind.  This field
 *     must be present, and its value must be a string containing the
 *     authentication ID.  Authentication ID values typically take the form
 *     "dn:" followed by the user DN, or "u:" followed by the username.
 *   </LI>
 *   <LI>
 *     "password" -- The password to use to bind to the server.  If this field
 *     is present, then its value must be a string that contains the clear-text
 *     password, or an empty string to indicate anonymous simple
 *     authentication.  If it is not provided, then the "password-file" field
 *     must be used to specify the path to a file containing the bind password.
 *   </LI>
 *   <LI>
 *     "password-file" -- The path to a file containing the password to use to
 *     bind to the server.  If this field is present, then its value must be a
 *     string that represents the path to a file containing a single line that
 *     contains the clear-text password.  If it is not provided, then the
 *     "password" field must be used to specify the password.
 *   </LI>
 * </UL>
 * For Example:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "single-server":
 *       {
 *         "address":"ldap.example.com",
 *         "port":389
 *       }
 *     },
 *     "authentication-details":
 *     {
 *       "authentication-type":"CRAM-MD5",
 *       "authentication-id":"u:john.doe",
 *       "password-file":"/path/to/password.txt"
 *     }
 *   }
 * </PRE>
 * <BR>
 * <B>The "DIGEST-MD5" Authentication Type</B>
 * If you wish to authenticate connections with the DIGEST-MD5 SASL mechanism,
 * then you can specify an "authentication-type" value of "DIGEST-MD5".  The
 * following additional fields may be included in the "authentication-details"
 * object for this authentication type:
 * <UL>
 *   <LI>
 *     "authentication-id" -- The authentication ID to use to bind.  This field
 *     must be present, and its value must be a string containing the
 *     authentication ID.  Authentication ID values typically take the form
 *     "dn:" followed by the user DN, or "u:" followed by the username.
 *   </LI>
 *   <LI>
 *     "authorization-id" -- The alternate authorization identity to use for the
 *     connection after the bind has completed.  If present, the value must be
 *     a string containing the desired authorization identity.  If this field is
 *     absent, then no alternate authorization identity will be used.
 *   </LI>
 *   <LI>
 *     "password" -- The password to use to bind to the server.  If this field
 *     is present, then its value must be a string that contains the clear-text
 *     password, or an empty string to indicate anonymous simple
 *     authentication.  If it is not provided, then the "password-file" field
 *     must be used to specify the path to a file containing the bind password.
 *   </LI>
 *   <LI>
 *     "password-file" -- The path to a file containing the password to use to
 *     bind to the server.  If this field is present, then its value must be a
 *     string that represents the path to a file containing a single line that
 *     contains the clear-text password.  If it is not provided, then the
 *     "password" field must be used to specify the password.
 *   </LI>
 *   <LI>
 *     "realm" -- The realm to use for the bind request.  If this field is
 *     present, then its value must be a string containing the name of the
 *     realm.  If it is not provided, then the realm will not be included in the
 *     bind request.
 *   </LI>
 *   <LI>
 *     "qop" -- The allowed quality of protection value(s) that may be used for
 *     the bind operation.  If this field is present, then its value may be a
 *     single string or an array of strings indicating the allowed QoP values.
 *     Allowed values include "auth" (for just authentication), "auth-int" (for
 *     authentication followed by integrity protection for subsequent
 *     communication on the connection), and "auth-conf" (for authentication
 *     followed by confidentiality for subsequent communication on the
 *     connection).  If this field is not present, then a default value of
 *     "auth" will be assumed.
 *   </LI>
 * </UL>
 * For Example:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "single-server":
 *       {
 *         "address":"ldap.example.com",
 *         "port":389
 *       }
 *     },
 *     "authentication-details":
 *     {
 *       "authentication-type":"DIGEST-MD5",
 *       "authentication-id":"u:john.doe",
 *       "password-file":"/path/to/password.txt"
 *     }
 *   }
 * </PRE>
 * <BR>
 * <B>The "EXTERNAL" Authentication Type</B>
 * If you wish to authenticate connections with the EXTERNAL SASL mechanism,
 * then you can specify an "authentication-type" value of "EXTERNAL".  The
 * connection must be secured with SSL or StartTLS, and the following additional
 * field may be present in the "authentication-details" object:
 * <UL>
 *   <LI>
 *     "authorization-id" -- The authorization identity for the bind request.
 *     If this field is present, then it must be a string containing the
 *     desired authorization ID, or an empty string if the server should
 *     determine the authorization identity.  If this field is omitted, then
 *     the bind request will not include any SASL credentials, which may be
 *     required for use with some servers that cannot handle the possibility of
 *     an authorization ID in the bind request.
 *   </LI>
 * </UL>
 * For Example:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "single-server":
 *       {
 *         "address":"ldap.example.com",
 *         "port":636
 *       }
 *     },
 *     "communication-security":
 *     {
 *       "security-type":"SSL",
 *       "use-jvm-default-trust-store":true,
 *       "trust-store-file":"/path/to/trust-store.jks",
 *       "trust-store-type":"JKS",
 *       "verify-address-in-certificate":true
 *     },
 *     "authentication-details":
 *     {
 *       "authentication-type":"EXTERNAL",
 *       "authorization-id":""
 *     }
 *   }
 * </PRE>
 * <BR>
 * <B>The "GSSAPI" Authentication Type</B>
 * If you wish to authenticate connections with the GSSAPI SASL mechanism,
 * then you can specify an "authentication-type" value of "GSSAPI".  The
 * following additional fields may be included in the "authentication-details"
 * object for this authentication type:
 * <UL>
 *   <LI>
 *     "authentication-id" -- The authentication ID to use to bind.  This field
 *     must be present, and its value must be a string containing the
 *     authentication ID.  Authentication ID values for a GSSAPI bind request
 *     are typically the Kerberos principal for the user to authenticate.
 *   </LI>
 *   <LI>
 *     "authorization-id" -- The alternate authorization identity to use for the
 *     connection after the bind has completed.  If present, the value must be
 *     a string containing the desired authorization identity.  If this field is
 *     absent, then no alternate authorization identity will be used.
 *   </LI>
 *   <LI>
 *     "password" -- The password to use to bind to the server.  If this field
 *     is present, then its value must be a string that contains the clear-text
 *     password, or an empty string to indicate anonymous simple
 *     authentication.  If it is not provided, then the "password-file" field
 *     may be used to specify the path to a file containing the bind password.
 *     If authentication will require the use of cached credentials, then the
 *     password may be omitted.
 *   </LI>
 *   <LI>
 *     "password-file" -- The path to a file containing the password to use to
 *     bind to the server.  If this field is present, then its value must be a
 *     string that represents the path to a file containing a single line that
 *     contains the clear-text password.  If it is not provided, then the
 *     "password" field may be used to specify the password.  If authentication
 *     will require the use of cached credentials, then the password may be
 *     omitted.
 *   </LI>
 *   <LI>
 *     "realm" -- The realm to use for the bind request.  If this field is
 *     present, then its value must be a string containing the name of the
 *     realm.  If it is not provided, then the JVM will attempt to determine the
 *     realm from the underlying system configuration.
 *   </LI>
 *   <LI>
 *     "qop" -- The allowed quality of protection value(s) that may be used for
 *     the bind operation.  If this field is present, then its value may be a
 *     single string or an array of strings indicating the allowed QoP values.
 *     Allowed values include "auth" (for just authentication), "auth-int" (for
 *     authentication followed by integrity protection for subsequent
 *     communication on the connection), and "auth-conf" (for authentication
 *     followed by confidentiality for subsequent communication on the
 *     connection).  If this field is not present, then a default value of
 *     "auth" will be assumed.
 *   </LI>
 *   <LI>
 *     "kdc-address" -- The address of the Kerberos KDC to use during
 *     authentication.  If this field is present, then its value must be a
 *     string containing the target address.  If it is not provided, then the
 *     JVM will attempt to determine the address of the KDC from the underlying
 *     system configuration.
 *   </LI>
 *   <LI>
 *     "config-file-path" --  The path to a JAAS configuration file to use for
 *     bind processing.  If this field is present, then its value must be a
 *     string containing the path to a valid JAAS configuration file.  If it is
 *     not provided, a temporary JAAS configuration file will be created for the
 *     bind operation.
 *   </LI>
 *   <LI>
 *     "renew-tgt" -- Indicates whether successful authentication should attempt
 *     to renew the ticket-granting ticket for an existing session.  If this
 *     field is present, then its value must be a boolean.  If it is not
 *     provided, then a default of {@code false} will be assumed.
 *   </LI>
 *   <LI>
 *     "require-cached-credentials" -- Indicates whether the authentication
 *     process should require the use of cached credentials leveraged from an
 *     existing Kerberos session rather than try to create a new session.  if
 *     this field is present, then its value must be a boolean.  If it is not
 *     provided, then a default of {@code false} will be assumed.
 *   </LI>
 *   <LI>
 *     "use-ticket-cache" -- Indicates whether the authentication process should
 *     leverage a ticket cache in order to leverage an existing Kerberos
 *     session if the user has already authenticated to the KDC.  If present,
 *     then its value must be a boolean.  If it is not provided, then a default
 *     of {@code true} will be used.
 *   </LI>
 *   <LI>
 *     "ticket-cache-path" -- Specifies the path to the Kerberos ticket cache to
 *     use.  If this is provided, its value must be a string with the path to
 *     the desired ticket cache.  If it is not provided, then the JVM will
 *     attempt to determine the appropriate ticket cache from the underlying
 *     system configuration.
 *   </LI>
 *   <LI>
 *     "use-subject-credentials-only" -- Indicates whether authentication should
 *     require the client will be required to use credentials that match the
 *     current subject.  If it is provided, then the value must be a boolean.
 *     If it is not provided, then a default of {@code true} will be assumed.
 *   </LI>
 * </UL>
 * For Example:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "single-server":
 *       {
 *         "address":"ldap.example.com",
 *         "port":389
 *       }
 *     },
 *     "authentication-details":
 *     {
 *       "authentication-type":"GSSAPI",
 *       "authentication-id":"john.doe@EXAMPLE.COM",
 *       "password-file":"/path/to/password.txt",
 *       "renew-tgt":true
 *     }
 *   }
 * </PRE>
 * <BR>
 * <B>The "PLAIN" Authentication Type</B>
 * If you wish to authenticate connections with the PLAIN SASL mechanism,
 * then you can specify an "authentication-type" value of "PLAIN".  The
 * following additional fields may be included in the "authentication-details"
 * object for this authentication type:
 * <UL>
 *   <LI>
 *     "authentication-id" -- The authentication ID to use to bind.  This field
 *     must be present, and its value must be a string containing the
 *     authentication ID.  Authentication ID values typically take the form
 *     "dn:" followed by the user DN, or "u:" followed by the username.
 *   </LI>
 *   <LI>
 *     "authorization-id" -- The alternate authorization identity to use for the
 *     connection after the bind has completed.  If present, the value must be
 *     a string containing the desired authorization identity.  If this field is
 *     absent, then no alternate authorization identity will be used.
 *   </LI>
 *   <LI>
 *     "password" -- The password to use to bind to the server.  If this field
 *     is present, then its value must be a string that contains the clear-text
 *     password, or an empty string to indicate anonymous simple
 *     authentication.  If it is not provided, then the "password-file" field
 *     must be used to specify the path to a file containing the bind password.
 *   </LI>
 *   <LI>
 *     "password-file" -- The path to a file containing the password to use to
 *     bind to the server.  If this field is present, then its value must be a
 *     string that represents the path to a file containing a single line that
 *     contains the clear-text password.  If it is not provided, then the
 *     "password" field must be used to specify the password.
 *   </LI>
 * </UL>
 * For Example:
 * <PRE>
 *   {
 *     "server-details":
 *     {
 *       "single-server":
 *       {
 *         "address":"ldap.example.com",
 *         "port":389
 *       }
 *     },
 *     "authentication-details":
 *     {
 *       "authentication-type":"PLAIN",
 *       "authentication-id":"dn:uid=john.doe,ou=People,dc=example,dc=com",
 *       "password-file":"/path/to/password.txt"
 *     }
 *   }
 * </PRE>
 * <BR>
 * The "authentication-details" field is optional, and if it is omitted from the
 *  specification then no authentication will be performed.
 * <BR><BR>
 * <H2>The "connection-pool-options" Section</H2>
 * The "connection-pool-options" section may be used to provide information
 * about a number of settings that may be used in the course of creating or
 * maintaining a connection pool.  The value of the "connection-pool-options"
 * field must be a JSON object, and the following fields may appear in that
 * object:
 * <UL>
 *   <LI>
 *     "create-if-necessary" -- Indicates whether the connection pool should
 *     create a new connection if one is needed but none are available.  If
 *     present, the value must be a boolean.  If it is absent, then a default
 *     of {@code true} will be assumed.
 *   </LI>
 *   <LI>
 *     "health-check-get-entry-dn" -- The DN of an entry that should be
 *     retrieved during health check processing.  If present, the value must be
 *     a string that represents the DN of the entry to retrieve, or an empty
 *     string to indicate that the server root DSE should be retrieved.  If this
 *     field is absent, then no entry will be retrieved during health check
 *     processing.
 *   </LI>
 *   <LI>
 *     "health-check-get-entry-maximum-response-time-millis" -- The maximum
 *     length of time in milliseconds to wait for the entry to be returned in a
 *     get entry health check.  If present, the value must be a positive
 *     integer.  If it is not provided, then a default of 10000 (ten seconds)
 *     will be used.
 *   </LI>
 *   <LI>
 *     "initial-connect-threads" -- The number of threads to use when creating
 *     the initial set of connections for the pool.  If this field is present,
 *     then the value must be a positive integer, with a value of one indicating
 *     that connection should be created in a single-threaded manner, and a
 *     value greater than one indicating that the initial connections should be
 *     established in parallel.  If it is not provided, then a default of one
 *     will be used.
 *   </LI>
 *   <LI>
 *     "invoke-background-health-checks" -- Indicates whether the connection
 *     pool should periodically invoke health check processing on idle
 *     connections.  If this field is present, then its value must be a boolean.
 *     If it is not present, then a default of {@code true} will be assumed.
 *   </LI>
 *   <LI>
 *     "invoke-checkout-health-checks" -- Indicates whether the connection pool
 *     should invoke health check processing on connections just before they are
 *     checked out of the pool to ensure that they are valid.  If this field is
 *     present, then its value must be a boolean.  If it is not present, then a
 *     default of {@code false} will be assumed.
 *   </LI>
 *   <LI>
 *     "invoke-create-health-checks" -- Indicates whether the connection pool
 *     should invoke health check processing on connections just after they are
 *     created.  If this field is present, then its value must be a boolean.  If
 *     it is not present, then a default of {@code false} will be assumed.
 *   </LI>
 *   <LI>
 *     "invoke-authentication-health-checks" -- Indicates whether the connection
 *     pool should invoke health check processing on connections just after they
 *     have been authenticated.  This includes after a successful bind on a
 *     newly-created connection, and after calls to the connection pool's
 *     {@code bindAndRevertAuthentication} and
 *     {@code releaseAndReAuthenticateConnection} methods.  If this field is
 *     present, then its value must be a boolean.  If it is not present, then a
 *     default of {@code false} will be assumed.
 *   </LI>
 *   <LI>
 *     "invoke-exception-health-checks" -- Indicates whether the connection pool
 *     should invoke health check processing on connections just after an
 *     exception is caught that might indicate that the connection is no longer
 *     valid.  Note that this only applies to exceptions caught during
 *     operations processed directly against the connection pool and not to
 *     exceptions caught on a connection checked out of the pool.  If this field
 *     is present, then its value must be a boolean.  If it is not present, then
 *     a default of {@code true} will be assumed.
 *   </LI>
 *   <LI>
 *     "invoke-release-health-checks" -- Indicates whether the connection pool
 *     should invoke health check processing on connections just before they are
 *     released back to the pool to ensure that they are valid.  If this field
 *     is present, then its value must be a boolean.  If it is not present, then
 *     a default of {@code false} will be assumed.
 *   </LI>
 *   <LI>
 *     "maximum-connection-age-millis" -- Specifies the maximum length of time
 *     (in milliseconds) that a connection should be allowed to remain
 *     established before it is eligible to be closed and replaced with a
 *     newly-created connection.  If present, then the value must be a positive
 *     integer to specify the maximum age, or zero to indicate that no maximum
 *     age should be applied.  If it is not present, then a default value of
 *     zero will be used.
 *   </LI>
 *   <LI>
 *     "maximum-defunct-replacement-connection-age-millis" -- Specifies the
 *     maximum connection age (in milliseconds) that should be used for
 *     connections created to replace a defunct connection.  If present, then
 *     the value must be a positive integer to specify the maximum age, or zero
 *     to indicate that no maximum age should be applied.  If it is not present,
 *     then the value of the "maximum-connection-age-millis" field will be used
 *     for connections created as replacements for defunct connections.
 *   </LI>
 *   <LI>
 *     "maximum-wait-time-millis" -- Specifies the maximum length of time (in
 *     milliseconds) that the pool should wait for a connection to be released
 *     if one is needed but none are immediately available.  If present, then
 *     this value must be a positive integer to specify the length of time to
 *     wait, or zero to indicate that it should not wait at all.  If it is not
 *     provided, then a default value of zero will be used.
 *   </LI>
 *   <LI>
 *     "retry-failed-operations-due-to-invalid-connections" -- Indicates whether
 *     the pool should automatically attempt to retry operations attempted
 *     directly against the pool (but not for connections checked out of the
 *     pool) if the initial attempt fails in a manner that may indicate that the
 *     connection is no longer valid.  If this field is present, then its value
 *     may be either a boolean to indicate whether to enable retry for all types
 *     of operations or no operations, or it may be an array of strings
 *     indicating the operation types ("add", "bind", "compare", "delete",
 *     "extended", "modify", "modify-dn", or "search") that should be retried
 *     in the event of a failure.  If this field is not present, then no
 *     automatic retry will be attempted.
 *   </LI>
 * </UL>
 * <BR>
 * The "connection-pool-options" field is optional, and if it is omitted from
 * the specification then the default values will be used for all options.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPConnectionDetailsJSONSpecification
{
  /**
   * The name of the top-level field that may be used to provide information to
   * use to authenticate connections to the server.
   */
  @NotNull static final String FIELD_AUTHENTICATION_DETAILS =
       "authentication-details";



  /**
   * The name of the top-level field that may be used to provide information
   * about the type of communication security that should be used.
   */
  @NotNull static final String FIELD_COMMUNICATION_SECURITY =
       "communication-security";



  /**
   * The name of the top-level field that may be used to provide information
   * about options that should be set when establishing connections.
   */
  @NotNull static final String FIELD_CONNECTION_OPTIONS = "connection-options";



  /**
   * The name of the top-level field that may be used to provide information
   * about options that should be set when creating a connection pool.
   */
  @NotNull static final String FIELD_CONNECTION_POOL_OPTIONS =
       "connection-pool-options";



  /**
   * The name of the top-level field that may be used to provide information
   * about the directory server(s) to which the connection should be
   * established.
   */
  @NotNull static final String FIELD_SERVER_DETAILS = "server-details";



  // The bind request that will be used to authenticate connections.
  @Nullable private final BindRequest bindRequest;

  // The processed connection pool options portion of the specification.
  @NotNull private final ConnectionPoolOptions connectionPoolOptionsSpec;

  // The processed security options portion of the specification.
  @NotNull private final SecurityOptions securityOptionsSpec;

  // The server set that will be used to create connections.
  @NotNull private final ServerSet serverSet;



  /**
   * Creates a new LDAP connection details object from the specification
   * contained in the provided JSON object.
   *
   * @param  connectionDetailsObject  The JSON object that contains information
   *                                  that may be used to create LDAP
   *                                  connections.
   *
   * @throws  LDAPException  If the provided JSON object does not contain a
   *                         valid connection details specification.
   */
  public LDAPConnectionDetailsJSONSpecification(
              @NotNull final JSONObject connectionDetailsObject)
         throws LDAPException
  {
    validateTopLevelFields(connectionDetailsObject);

    try
    {
      securityOptionsSpec = new SecurityOptions(connectionDetailsObject);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPException(le.getResultCode(),
           ERR_LDAP_SPEC_ERROR_PROCESSING_FIELD.get(
                FIELD_COMMUNICATION_SECURITY, le.getMessage()),
           le);
    }

    final ConnectionOptions connectionOptionsSpec;
    try
    {
      connectionOptionsSpec = new ConnectionOptions(connectionDetailsObject);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPException(le.getResultCode(),
           ERR_LDAP_SPEC_ERROR_PROCESSING_FIELD.get(
                FIELD_CONNECTION_OPTIONS, le.getMessage()),
           le);
    }

    try
    {
      final ServerDetails serverDetailsSpec =
           new ServerDetails(connectionDetailsObject, securityOptionsSpec,
                connectionOptionsSpec);
      serverSet = serverDetailsSpec.getServerSet();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPException(le.getResultCode(),
           ERR_LDAP_SPEC_ERROR_PROCESSING_FIELD.get(
                FIELD_SERVER_DETAILS, le.getMessage()),
           le);
    }

    try
    {
      final AuthenticationDetails authenticationDetailsSpec =
           new AuthenticationDetails(connectionDetailsObject);
      bindRequest = authenticationDetailsSpec.getBindRequest();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPException(le.getResultCode(),
           ERR_LDAP_SPEC_ERROR_PROCESSING_FIELD.get(
                FIELD_AUTHENTICATION_DETAILS, le.getMessage()),
           le);
    }

    try
    {
      connectionPoolOptionsSpec =
           new ConnectionPoolOptions(connectionDetailsObject);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPException(le.getResultCode(),
           ERR_LDAP_SPEC_ERROR_PROCESSING_FIELD.get(
                FIELD_CONNECTION_POOL_OPTIONS, le.getMessage()),
           le);
    }
  }



  /**
   * Creates a new LDAP connection details object from the specification
   * contained in the JSON object represented by the given string.
   *
   * @param  jsonString  The string representation of the JSON object that
   *                     contains information that may be used to create LDAP
   *                     connections.
   *
   * @return  The LDAP connection details object parsed from the provided
   *          JSON object string.
   *
   * @throws  JSONException  If the provided string cannot be parsed as a valid
   *                         JSON object.
   *
   * @throws  LDAPException  If the parsed JSON object does not contain a valid
   *                         connection details specification.
   */
  @NotNull()
  public static LDAPConnectionDetailsJSONSpecification fromString(
                     @NotNull final String jsonString)
         throws JSONException, LDAPException
  {
    return new LDAPConnectionDetailsJSONSpecification(
         new JSONObject(jsonString));
  }



  /**
   * Creates a new LDAP connection details object from the specification
   * contained in the JSON object read from the indicated file.
   *
   * @param  path  The path to a file containing a JSON object with information
   *               that may be used to create LDAP connections.
   *
   * @return  The LDAP connection details object parsed from the information in
   *          the specified file.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       specified file.
   *
   * @throws  JSONException  If the contents of the specified file cannot be
   *                         parsed as a valid JSON object.
   *
   * @throws  LDAPException  If the parsed JSON object does not contain a valid
   *                         connection details specification.
   */
  @NotNull()
  public static LDAPConnectionDetailsJSONSpecification fromFile(
                     @NotNull final String path)
         throws IOException, JSONException, LDAPException
  {
    return fromFile(new File(path));
  }



  /**
   * Creates a new LDAP connection details object from the specification
   * contained in the JSON object read from the indicated file.
   *
   * @param  file  The file containing a JSON object with information that may
   *               be used to create LDAP connections.
   *
   * @return  The LDAP connection details object parsed from the information in
   *          the specified file.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       specified file.
   *
   * @throws  JSONException  If the contents of the specified file cannot be
   *                         parsed as a valid JSON object.
   *
   * @throws  LDAPException  If the parsed JSON object does not contain a valid
   *                         connection details specification.
   */
  @NotNull()
  public static LDAPConnectionDetailsJSONSpecification fromFile(
                     @NotNull final File file)
         throws IOException, JSONException, LDAPException
  {
    return fromInputStream(new FileInputStream(file));
  }



  /**
   * Creates a new LDAP connection details object from the specification
   * contained in the JSON object read from the provided input stream.  The
   * entire contents of the stream must be exactly one JSON object.  Because the
   * input stream will be fully read, it will always be closed by this method.
   *
   * @param  inputStream  The input stream from which to read a JSON object with
   *                      information that may be used to create LDAP
   *                      connections.  The entire contents of the stream must
   *                      be exactly one JSON object.  Because the input stream
   *                      will be fully read, it will always be closed by this
   *                      method.
   *
   * @return  The LDAP connection details object parsed from the information
   *          read from the provided input stream.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       provided input stream.
   *
   * @throws  JSONException  If the contents of the specified file cannot be
   *                         parsed as a valid JSON object.
   *
   * @throws  LDAPException  If the parsed JSON object does not contain a valid
   *                         connection details specification.
   */
  @NotNull()
  public static LDAPConnectionDetailsJSONSpecification fromInputStream(
                     @NotNull final InputStream inputStream)
         throws IOException, JSONException, LDAPException
  {
    try
    {
      final ByteStringBuffer b = new ByteStringBuffer();
      final byte[] readBuffer = new byte[8192];
      while (true)
      {
        final int bytesRead = inputStream.read(readBuffer);
        if (bytesRead < 0)
        {
          break;
        }
        else
        {
          b.append(readBuffer, 0, bytesRead);
        }
      }

      return new LDAPConnectionDetailsJSONSpecification(
           new JSONObject(b.toString()));
    }
    finally
    {
      inputStream.close();
    }
  }



  /**
   * Retrieves the server set that may be used to create new connections based
   * on the JSON specification.
   *
   * @return  The server set that may be used to create new connections based on
   *          the JSON specification.
   */
  @NotNull()
  public ServerSet getServerSet()
  {
    return serverSet;
  }



  /**
   * Retrieves the bind request that may be used to authenticate connections
   * created from the JSON specification.
   *
   * @return  The bind request that may be used to authenticate connections
   *          created from the JSON specification, or {@code null} if the
   *          connections should be unauthenticated.
   */
  @Nullable()
  public BindRequest getBindRequest()
  {
    return bindRequest;
  }



  /**
   * Creates a new LDAP connection based on the JSON specification.  The
   * connection will be authenticated if appropriate.
   *
   * @return  The LDAP connection that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         establish or authenticate the connection.
   */
  @NotNull()
  public LDAPConnection createConnection()
         throws LDAPException
  {
    final LDAPConnection connection = createUnauthenticatedConnection();

    if (bindRequest != null)
    {
      try
      {
        connection.bind(bindRequest);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        connection.close();
        throw le;
      }
    }

    return connection;
  }



  /**
   * Creates a new LDAP connection based on the JSON specification.  No
   * authentication will be performed on the connection.
   *
   * @return  The LDAP connection that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         establish the connection.
   */
  @NotNull()
  public LDAPConnection createUnauthenticatedConnection()
         throws LDAPException
  {
    return serverSet.getConnection();
  }



  /**
   * Creates a new LDAP connection pool based on the JSON specification.  The
   * pooled connections will be authenticated if appropriate.
   *
   * @param  initialConnections  The number of connections that should be
   *                             established at the time the pool is created.
   * @param  maximumConnections  The maximum number of connections that should
   *                             be available in the pool at any time.
   *
   * @return  The LDAP connection pool that was created.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         create the connection pool.
   */
  @NotNull()
  public LDAPConnectionPool createConnectionPool(final int initialConnections,
                                                 final int maximumConnections)
         throws LDAPException
  {
    final LDAPConnectionPool connectionPool = new LDAPConnectionPool(serverSet,
         bindRequest, initialConnections, maximumConnections,
         connectionPoolOptionsSpec.getInitialConnectThreads(),
         securityOptionsSpec.getPostConnectProcessor(), false,
         connectionPoolOptionsSpec.getHealthCheck());

    connectionPoolOptionsSpec.applyConnectionPoolSettings(connectionPool);
    return connectionPool;
  }



  /**
   * Creates a new LDAP connection pool based on the JSON specification.  No
   * authentication will be used for connections that are part of the pool.
   *
   * @param  initialConnections  The number of connections that should be
   *                             established at the time the pool is created.
   * @param  maximumConnections  The maximum number of connections that should
   *                             be available in the pool at any time.
   *
   * @return  The LDAP connection pool that was created.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         create the connection pool.
   */
  @NotNull()
  public LDAPConnectionPool createUnauthenticatedConnectionPool(
                                 final int initialConnections,
                                 final int maximumConnections)
       throws LDAPException
  {
    final LDAPConnectionPool connectionPool = new LDAPConnectionPool(serverSet,
         null, initialConnections, maximumConnections,
         connectionPoolOptionsSpec.getInitialConnectThreads(),
         securityOptionsSpec.getPostConnectProcessor(), false,
         connectionPoolOptionsSpec.getHealthCheck());

    connectionPoolOptionsSpec.applyConnectionPoolSettings(connectionPool);
    return connectionPool;
  }



  /**
   * Validates the top-level fields in the provided JSON object to ensure that
   * all required fields are present and no unrecognized fields are present.
   *
   * @param  o  The JSON object to validate.
   *
   * @throws  LDAPException  If there is a problem with the set of top-level
   *                         fields in the provided JSON object.
   */
  private static void validateTopLevelFields(@NotNull final JSONObject o)
          throws LDAPException
  {
    boolean serverDetailsProvided = false;
    for (final String s : o.getFields().keySet())
    {
      if (s.equals(FIELD_SERVER_DETAILS))
      {
        // This is a required top-level field.
        serverDetailsProvided = true;
      }
      else if (s.equals(FIELD_CONNECTION_OPTIONS) ||
           s.equals(FIELD_COMMUNICATION_SECURITY) ||
           s.equals(FIELD_AUTHENTICATION_DETAILS) ||
           s.equals(FIELD_CONNECTION_POOL_OPTIONS))
      {
        // These are optional top-level fields.
      }
      else
      {
        // This is not a valid top-level field.
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAP_SPEC_UNRECOGNIZED_TOP_LEVEL_FIELD.get(s));
      }
    }

    if (! serverDetailsProvided)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LDAP_SPEC_MISSING_SERVER_DETAILS.get(FIELD_SERVER_DETAILS));
    }
  }



  /**
   * Validates that the set of fields contained in the JSON object that is the
   * value of the indicated field.
   *
   * @param  o  The JSON object to validate.
   * @param  f  The name of the field whose value is the provided JSON object.
   * @param  a  The names of the fields that are allowed to be present.
   *
   * @throws  LDAPException  If the provided JSON object contains any fields
   *                         that are not contained in the allowed set.
   */
  static void validateAllowedFields(@NotNull final JSONObject o,
                                    @NotNull final String f,
                                    @NotNull final String... a)
         throws LDAPException
  {
    final HashSet<String> s = new HashSet<>(Arrays.asList(a));
    for (final String n : o.getFields().keySet())
    {
      if (! s.contains(n))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAP_SPEC_UNRECOGNIZED_FIELD.get(n, f));
      }
    }
  }



  /**
   * Retrieves the value of the specified JSON object field as a boolean.
   *
   * @param  o  The object from which to retrieve the boolean value.
   * @param  f  The name of the field to retrieve.
   * @param  d  The default value to return if the specified field does not
   *            exist.
   *
   * @return  The requested boolean value.
   *
   * @throws  LDAPException  If the specified field exists but is not a boolean.
   */
  static boolean getBoolean(@NotNull final JSONObject o,
                            @NotNull final String f, final boolean d)
         throws LDAPException
  {
    final JSONValue v = o.getField(f);
    if (v == null)
    {
      return d;
    }

    if (v instanceof JSONBoolean)
    {
      return ((JSONBoolean) v).booleanValue();
    }
    else
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LDAP_SPEC_VALUE_NOT_BOOLEAN.get(f));
    }
  }



  /**
   * Retrieves the value of the specified JSON object field as an integer.
   *
   * @param  o  The object from which to retrieve the integer value.
   * @param  f  The name of the field to retrieve.
   * @param  d  The default value to return if the specified field does not
   *            exist.
   * @param  n  The minimum allowed value for the field, if any.
   * @param  x  The maximum allowed value for the field, if any.
   *
   * @return  The requested integer value.
   *
   * @throws  LDAPException  If the specified field exists but is not an
   *                         integer.
   */
  @Nullable()
  static Integer getInt(@NotNull final JSONObject o, @NotNull final String f,
                        @Nullable final Integer d, @Nullable final Integer n,
                        @Nullable final Integer x)
         throws LDAPException
  {
    final JSONValue v = o.getField(f);
    if (v == null)
    {
      return d;
    }

    if (v instanceof JSONNumber)
    {
      try
      {
        final int i =((JSONNumber) v).getValue().intValueExact();
        if ((n != null) && (i < n))
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_LDAP_SPEC_VALUE_BELOW_MIN.get(f, n));
        }

        if ((x != null) && (i > x))
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_LDAP_SPEC_VALUE_ABOVE_MAX.get(f, n));
        }

        return i;
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        throw le;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAP_SPEC_VALUE_NOT_INTEGER.get(f), e);
      }
    }
    else
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LDAP_SPEC_VALUE_NOT_INTEGER.get(f));
    }
  }



  /**
   * Retrieves the value of the specified JSON object field as a long.
   *
   * @param  o  The object from which to retrieve the long value.
   * @param  f  The name of the field to retrieve.
   * @param  d  The default value to return if the specified field does not
   *            exist.
   * @param  n  The minimum allowed value for the field, if any.
   * @param  x  The maximum allowed value for the field, if any.
   *
   * @return  The requested long value.
   *
   * @throws  LDAPException  If the specified field exists but is not a long.
   */
  @Nullable()
  static Long getLong(@NotNull final JSONObject o, @NotNull final String f,
                      @Nullable final Long d, @Nullable final Long n,
                      @Nullable final Long x)
         throws LDAPException
  {
    final JSONValue v = o.getField(f);
    if (v == null)
    {
      return d;
    }

    if (v instanceof JSONNumber)
    {
      try
      {
        final long l =((JSONNumber) v).getValue().longValueExact();
        if ((n != null) && (l < n))
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_LDAP_SPEC_VALUE_BELOW_MIN.get(f, n));
        }

        if ((x != null) && (l > x))
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_LDAP_SPEC_VALUE_ABOVE_MAX.get(f, n));
        }

        return l;
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        throw le;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAP_SPEC_VALUE_NOT_INTEGER.get(f), e);
      }
    }
    else
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LDAP_SPEC_VALUE_NOT_INTEGER.get(f));
    }
  }



  /**
   * Retrieves the value of the specified JSON object field as an object.
   *
   * @param  o  The object from which to retrieve the object value.
   * @param  f  The name of the field to retrieve.
   *
   * @return  The requested object value.
   *
   * @throws  LDAPException  If the specified field exists but is not an object.
   */
  @Nullable()
  static JSONObject getObject(@NotNull final JSONObject o,
                              @NotNull final String f)
         throws LDAPException
  {
    final JSONValue v = o.getField(f);
    if (v == null)
    {
      return null;
    }

    if (v instanceof JSONObject)
    {
      return (JSONObject) v;
    }
    else
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LDAP_SPEC_VALUE_NOT_OBJECT.get(f));
    }
  }



  /**
   * Retrieves the value of the specified JSON object field as a string.
   *
   * @param  o  The object from which to retrieve the string value.
   * @param  f  The name of the field to retrieve.
   * @param  d  The default value to return if the specified field does not
   *            exist.
   *
   * @return  The requested string value.
   *
   * @throws  LDAPException  If the specified field exists but is not a string.
   */
  @Nullable()
  static String getString(@NotNull final JSONObject o, @NotNull final String f,
                          @Nullable final String d)
         throws LDAPException
  {
    final JSONValue v = o.getField(f);
    if (v == null)
    {
      return d;
    }

    if (v instanceof JSONString)
    {
      return ((JSONString) v).stringValue();
    }
    else
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LDAP_SPEC_VALUE_NOT_STRING.get(f));
    }
  }



  /**
   * Retrieves a string value read from the specified file.  The file must
   * contain exactly one line, and that line must not be empty.
   *
   * @param  path       The path to the file from which to read the string.
   * @param  fieldName  The name of the field from which the path was obtained.
   *
   * @return  The string read from the specified file.
   *
   * @throws  LDAPException  If a problem is encountered while reading from the
   *                         specified file, if the file does not contain
   *                         exactly one line, or if the line contained in the
   *                         file is empty.
   */
  @NotNull()
  static String getStringFromFile(@NotNull final String path,
                                  @NotNull final String fieldName)
         throws LDAPException
  {
    BufferedReader r = null;
    try
    {
      r = new BufferedReader(new FileReader(path));

      final String line = r.readLine();
      if (line == null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAP_SPEC_READ_FILE_EMPTY.get(path, fieldName));
      }

      if (r.readLine() != null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAP_SPEC_READ_FILE_MULTIPLE_LINES.get(path, fieldName));
      }

      if (line.isEmpty())
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAP_SPEC_READ_FILE_EMPTY_LINE.get(path, fieldName));
      }

      return line;
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_LDAP_SPEC_READ_FILE_ERROR.get(path, fieldName,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
    finally
    {
      if (r != null)
      {
        try
        {
          r.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }
  }



  /**
   * Verifies that none of the indicated fields exist in the provided JSON
   * object because they would conflict with the specified existing field.
   *
   * @param  o                  The JSON object to examine.
   * @param  existingField      The name of a field known to be present in the
   *                            JSON object that cannot coexist with the
   *                            indicated conflicting fields.
   * @param  conflictingFields  The names of the fields that cannot be used in
   *                            conjunction with the specified existing field.
   *
   * @throws  LDAPException  If the provided JSON object has one or more fields
   *                         that conflict with the specified existing field.
   */
  static void rejectConflictingFields(@NotNull final JSONObject o,
                   @NotNull final String existingField,
                   @NotNull final String... conflictingFields)
         throws LDAPException
  {
    for (final String fieldName : conflictingFields)
    {
      if (o.getField(fieldName) != null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAP_SPEC_CONFLICTING_FIELD.get(fieldName, existingField));
      }
    }
  }



  /**
   * Verifies that none of the indicated fields exist in the provided JSON
   * object because they can only be provided if the specified required field is
   * present.
   *
   * @param  o                The JSON object to examine.
   * @param  requiredField    The name of a field known to be missing from the
   *                          JSON object, but must be present to allow any of
   *                          the indicated dependent fields to be provided.
   * @param  dependentFields  The names of the fields that can only be present
   *                          if the specified required field is present.
   *
   * @throws  LDAPException  If the provided JSON object has one or more
   *                         unresolved dependencies.
   */
  static void rejectUnresolvedDependency(@NotNull final JSONObject o,
                   @NotNull final String requiredField,
                   @NotNull final String... dependentFields)
         throws LDAPException
  {
    for (final String fieldName : dependentFields)
    {
      if (o.getField(fieldName) != null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_LDAP_SPEC_MISSING_DEPENDENT_FIELD.get(fieldName,
                  requiredField));
      }
    }
  }
}
