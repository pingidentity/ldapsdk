/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
 * This package provides a number of classes that can be used to parse X.509
 * certificates, PKCS #8 private keys, PKCS #10 certificate signing requests,
 * and other related entities.
 * <BR><BR>
 * This package also provides the
 * {@link com.unboundid.util.ssl.cert.ManageCertificates} class, which
 * implements a command-line tool for performing all kinds of
 * It also provides a manage-certificates command-line
 * tool that provides support for several certificate-related and key-related
 * functions, including:
 * <UL>
 *   <LI>
 *     Listing the contents of a JKS or PKCS #12 keystore.
 *   </LI>
 *   <LI>
 *     Exporting certificates and private keys from a JKS or PKCS #12 keystore
 *     to PEM or DER files.
 *   </LI>
 *   <LI>
 *     Importing certificates and private keys from PEM or DER files into a JKS
 *     or PKCS #12 keystore.
 *   </LI>
 *   <LI>
 *     Removing certificates and private keys from a JKS or PKCS #12 keystore.
 *   </LI>
 *   <LI>
 *     Generating self-signed certificates in JKS or PKCS #12 keystore.
 *   </LI>
 *   <LI>
 *     Generating certificate signing requests (CSRs) from a key in a JKS or
 *     PKCS #12 keystore (creating a new key if necessary).
 *   </LI>
 *   <LI>
 *     Signing certificate signing requests using a certificate in a JKS or
 *     PKCS #12 keystore.
 *   </LI>
 *   <LI>
 *     Changing the alias of a certificate or key in a JKS or PKCS #12 keystore.
 *   </LI>
 *   <LI>
 *     Connecting to a server, initiating TLS negotiation, capturing the
 *     certificate chain presented during that negotiation process, and
 *     importing the chain into a JKS or PKCS #12 keystore so that it can be
 *     used as a trust store for TLS clients.
 *   </LI>
 *   <LI>
 *     Validating the suitability of a specified certificate in a JKS or
 *     PKCS #12 keystore for use as a TLS sever certificate.
 *   </LI>
 *   <LI>
 *     Decoding and printing a set of PEM-formatted or DER-formatted
 *     certificates contained in a specified file.
 *   </LI>
 *   <LI>
 *     Decoding and printing a PEM-formatted or DER-formatted certificate
 *     signing request contained in a specified file.
 *   </LI>
 * </UL>
 */
package com.unboundid.util.ssl.cert;
