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
package com.unboundid.util.ssl.cert;



import java.io.Serializable;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.OID;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a helper class for building {@link GeneralNames} values.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class GeneralNamesBuilder
      implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5005719526010439377L;



  // The set of EDI party name values.
  @NotNull private final List<ASN1Element> ediPartyNames;

  // The set of X.400 name values.
  @NotNull private final List<ASN1Element> x400Addresses;

  // The set of directory name values.
  @NotNull private final List<DN> directoryNames;

  // The set of IP address values.
  @NotNull private final List<InetAddress> ipAddresses;

  // The other names included in the extension.
  @NotNull private final List<ObjectPair<OID,ASN1Element>> otherNames;

  // The registered IDs included in the extension.
  @NotNull private final List<OID> registeredIDs;

  // The DNS names included in the extension.
  @NotNull private final List<String> dnsNames;

  // The RFC 822 names (email addresses) in the extension.
  @NotNull private final List<String> rfc822Names;

  // The uniform resource identifiers in the extension.
  @NotNull private final List<String> uniformResourceIdentifiers;



  /**
   * Creates a new general names builder with no values.
   */
  GeneralNamesBuilder()
  {
    ediPartyNames = new ArrayList<>(5);
    x400Addresses = new ArrayList<>(5);
    directoryNames = new ArrayList<>(5);
    ipAddresses = new ArrayList<>(5);
    otherNames = new ArrayList<>(5);
    registeredIDs = new ArrayList<>(5);
    dnsNames = new ArrayList<>(5);
    rfc822Names = new ArrayList<>(5);
    uniformResourceIdentifiers = new ArrayList<>(5);
  }



  /**
   * Retrieves the set of other name values.
   *
   * @return  The set of other name values.
   */
  @NotNull()
  List<ObjectPair<OID,ASN1Element>> getOtherNames()
  {
    return otherNames;
  }



  /**
   * Adds the provided value to the set of other names.
   *
   * @param  oid    The OID for the other name element.  It must not be
   *                {@code null}.
   * @param  value  The value for the other name element.  It must not be
   *                {@code null}.
   *
   * @return  A reference to this object so that calls may be chained.
   */
  @NotNull()
  GeneralNamesBuilder addOtherName(@NotNull final OID oid,
                                   @NotNull final ASN1Element value)
  {
    otherNames.add(new ObjectPair<>(oid, value));
    return this;
  }



  /**
   * Retrieves the set of RFC 822 name (email address) values.
   *
   * @return  The set of RFC 822 name values.
   */
  @NotNull()
  List<String> getRFC822Names()
  {
    return rfc822Names;
  }



  /**
   * Adds the provided email address to the set of RFC 822 names.
   *
   * @param  emailAddress  The email address to add to the set of RFC 822 names.
   *                       It must not be {@code null}.
   *
   * @return  A reference to this object so that calls may be chained.
   */
  @NotNull()
  GeneralNamesBuilder addRFC822Name(@NotNull final String emailAddress)
  {
    rfc822Names.add(emailAddress);
    return this;
  }



  /**
   * Retrieves the set of DNS name values.
   *
   * @return  The set of DNS name values.
   */
  @NotNull()
  List<String> getDNSNames()
  {
    return dnsNames;
  }



  /**
   * Adds the provided name to the set of DNS name values.
   *
   * @param  dnsName  The name to add to the set of DNS name values.  It must
   *                  not be {@code null}.
   *
   * @return  A reference to this object so that calls may be chained.
   */
  @NotNull()
  GeneralNamesBuilder addDNSName(@NotNull final String dnsName)
  {
    dnsNames.add(dnsName);
    return this;
  }



  /**
   * Retrieves the set of X.400 address values.
   *
   * @return  The set of X.400 address values.
   */
  @NotNull()
  List<ASN1Element> getX400Addresses()
  {
    return x400Addresses;
  }



  /**
   * Adds the provided value to the set of X.400 address values.
   *
   * @param  x400Address  The value to add to the set of X.400 address values.
   *                      It must not be {@code null}.
   *
   * @return  A reference to this object so that calls may be chained.
   */
  @NotNull()
  GeneralNamesBuilder addX400Address(@NotNull final ASN1Element x400Address)
  {
    x400Addresses.add(x400Address);
    return this;
  }



  /**
   * Retrieves the set of directory name values.
   *
   * @return  The set of directory name values.
   */
  @NotNull()
  List<DN> getDirectoryNames()
  {
    return directoryNames;
  }



  /**
   * Adds the provided DN to the set of directory name values.
   *
   * @param  dn  The DN to add to the set of directory name values.  It must not
   *             be {@code null}.
   *
   * @return  A reference to this object so that calls may be chained.
   */
  @NotNull()
  GeneralNamesBuilder addDirectoryName(@NotNull final DN dn)
  {
    directoryNames.add(dn);
    return this;
  }



  /**
   * Retrieves the set of EDI party name values.
   *
   * @return  The set of EDI party name values.
   */
  @NotNull()
  List<ASN1Element> getEDIPartyNames()
  {
    return ediPartyNames;
  }



  /**
   * Adds the provided value to the set of EDI party name values.
   *
   * @param  value  The value to add to the set of EDI party name values.  It
   *                must not be {@code null}.
   *
   * @return  A reference to this object so that calls may be chained.
   */
  @NotNull()
  GeneralNamesBuilder addEDIPartyName(@NotNull final ASN1Element value)
  {
    ediPartyNames.add(value);
    return this;
  }



  /**
   * Retrieves the set of uniform resource identifier (URI) values.
   *
   * @return  The set of uniform resource identifier (URI) values.
   */
  @NotNull()
  List<String> getUniformResourceIdentifiers()
  {
    return uniformResourceIdentifiers;
  }



  /**
   * Adds the provided URI to the set of uniform resource identifier values.
   *
   * @param  uri  The URI to add to the set of uniform resource identifier
   *              values.  It must not be {@code null}.
   *
   * @return  A reference to this object so that calls may be chained.
   */
  @NotNull()
  GeneralNamesBuilder addUniformResourceIdentifier(@NotNull final String uri)
  {
    uniformResourceIdentifiers.add(uri);
    return this;
  }



  /**
   * Retrieves the set of IP address values.
   *
   * @return  The set of IP address values.
   */
  @NotNull()
  List<InetAddress> getIPAddresses()
  {
    return ipAddresses;
  }



  /**
   * Adds the provided IP address to the set of IP addresses.
   *
   * @param  ipAddress  The IP address to add to the set of IP address values.
   *                    It must not be {@code null}.
   *
   * @return  A reference to this object so that calls may be chained.
   */
  @NotNull()
  GeneralNamesBuilder addIPAddress(@NotNull final InetAddress ipAddress)
  {
    ipAddresses.add(ipAddress);
    return this;
  }



  /**
   * Retrieves the set of registered ID values.
   *
   * @return  The set of registered ID values.
   */
  @NotNull()
  List<OID> getRegisteredIDs()
  {
    return registeredIDs;
  }



  /**
   * Adds the provided ID to the set of registered ID values.
   *
   * @param  id  The ID to add to the set of registered ID values.  It must not
   *             be {@code null}.
   *
   * @return  A reference to this object so that calls may be chained.
   */
  @NotNull()
  GeneralNamesBuilder addRegisteredID(@NotNull final OID id)
  {
    registeredIDs.add(id);
    return this;
  }



  /**
   * Creates a {@code GeneralNames} object from the information in this builder.
   *
   * @return  The {@code GeneralNames} value created from this builder.
   */
  @NotNull()
  GeneralNames build()
  {
    return new GeneralNames(
         Collections.unmodifiableList(new ArrayList<>(otherNames)),
         Collections.unmodifiableList(new ArrayList<>(rfc822Names)),
         Collections.unmodifiableList(new ArrayList<>(dnsNames)),
         Collections.unmodifiableList(new ArrayList<>(x400Addresses)),
         Collections.unmodifiableList(new ArrayList<>(directoryNames)),
         Collections.unmodifiableList(new ArrayList<>(ediPartyNames)),
         Collections.unmodifiableList(new ArrayList<>(
              uniformResourceIdentifiers)),
         Collections.unmodifiableList(new ArrayList<>(ipAddresses)),
         Collections.unmodifiableList(new ArrayList<>(registeredIDs)));
  }
}
