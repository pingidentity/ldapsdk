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
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1IA5String;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.OID;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides a data structure that represents a {@code GeneralNames}
 * element that may appear in a number of X.509 certificate extensions,
 * including {@link SubjectAlternativeNameExtension},
 * {@link IssuerAlternativeNameExtension},
 * {@link AuthorityKeyIdentifierExtension}, and
 * {@link CRLDistributionPointsExtension}.  The {@code GeneralNames} element has
 * the following encoding (as described in
 * <A HREF="https://www.ietf.org/rfc/rfc5280.txt">RFC 5280</A> section 4.2.1.6):
 * <PRE>
 *   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 *   GeneralName ::= CHOICE {
 *        otherName                       [0]     OtherName,
 *        rfc822Name                      [1]     IA5String,
 *        dNSName                         [2]     IA5String,
 *        x400Address                     [3]     ORAddress,
 *        directoryName                   [4]     Name,
 *        ediPartyName                    [5]     EDIPartyName,
 *        uniformResourceIdentifier       [6]     IA5String,
 *        iPAddress                       [7]     OCTET STRING,
 *        registeredID                    [8]     OBJECT IDENTIFIER }
 *
 *   OtherName ::= SEQUENCE {
 *        type-id    OBJECT IDENTIFIER,
 *        value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 *   EDIPartyName ::= SEQUENCE {
 *        nameAssigner            [0]     DirectoryString OPTIONAL,
 *        partyName               [1]     DirectoryString }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GeneralNames
       implements Serializable
{
  /**
   * The DER type for otherName elements.
   */
  private static final byte NAME_TYPE_OTHER_NAME = (byte) 0xA0;



  /**
   * The DER type for rfc822Name elements.
   */
  private static final byte NAME_TYPE_RFC_822_NAME = (byte) 0x81;



  /**
   * The DER type for dNSName elements.
   */
  private static final byte NAME_TYPE_DNS_NAME = (byte) 0x82;



  /**
   * The DER type for x400Address elements.
   */
  private static final byte NAME_TYPE_X400_ADDRESS = (byte) 0xA3;



  /**
   * The DER type for directoryName elements.
   */
  private static final byte NAME_TYPE_DIRECTORY_NAME = (byte) 0xA4;



  /**
   * The DER type for ediPartyName elements.
   */
  private static final byte NAME_TYPE_EDI_PARTY_NAME = (byte) 0xA5;



  /**
   * The DER type for uniformResourceIdentifier elements.
   */
  private static final byte NAME_TYPE_UNIFORM_RESOURCE_IDENTIFIER = (byte) 0x86;



  /**
   * The DER type for ipAddress elements.
   */
  private static final byte NAME_TYPE_IP_ADDRESS = (byte) 0x87;



  /**
   * The DER type for registeredID elements.
   */
  private static final byte NAME_TYPE_REGISTERED_ID = (byte) 0x88;



  /**
   * The DER type for the value element in an otherName element.
   */
  private static final byte NAME_TYPE_OTHER_NAME_VALUE = (byte) 0xA0;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8789437423467093314L;



  // The EDI party names included in the extension.
  @NotNull private final List<ASN1Element> ediPartyNames;

  // The X.400 names included in the extension.
  @NotNull private final List<ASN1Element> x400Addresses;

  // The directory names included in the extension.
  @NotNull private final List<DN> directoryNames;

  // The IP addresses included in the extension.
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
   * Creates a new general names object from the provided information.
   *
   * @param  otherNames                  The list of other names to include in
   *                                     the object.  This must not be
   *                                     {@code null} but may be empty.
   * @param  rfc822Names                 The list of RFC 822 names (email
   *                                     addresses) to include in the object.
   *                                     This must not be {@code null} but may
   *                                     be empty.
   * @param  dnsNames                    The list of DNS name values to include
   *                                     in the object.  This must not be
   *                                     {@code null} but may be empty.
   * @param  x400Addresses               The list of X.400 address values to
   *                                     include in the object.  This must not
   *                                     be {@code null} but may be empty.
   * @param  directoryNames              The list of directory name values to
   *                                     include in the object.  This must not
   *                                     be {@code null} but may be empty.
   * @param  ediPartyNames               The list of EDI party name values to
   *                                     include in the object.  This must not
   *                                     be {@code null} but may be empty.
   * @param  uniformResourceIdentifiers  The list of uniform resource
   *                                     identifier values to include in the
   *                                     object.  This must not be {@code null}
   *                                     but may be empty.
   * @param  ipAddresses                 The list of IP address values to
   *                                     include in the object.  This must not
   *                                     be {@code null} but may be empty.
   * @param  registeredIDs               The list of registered ID values to
   *                                     include in the object.  This must not
   *                                     be {@code null} but may be empty.
   */
  GeneralNames(@NotNull final List<ObjectPair<OID,ASN1Element>> otherNames,
               @NotNull final List<String> rfc822Names,
               @NotNull final List<String> dnsNames,
               @NotNull final List<ASN1Element> x400Addresses,
               @NotNull final List<DN> directoryNames,
               @NotNull final List<ASN1Element> ediPartyNames,
               @NotNull final List<String> uniformResourceIdentifiers,
               @NotNull final List<InetAddress> ipAddresses,
               @NotNull final List<OID> registeredIDs)
  {
    this.otherNames = otherNames;
    this.rfc822Names = rfc822Names;
    this.dnsNames = dnsNames;
    this.x400Addresses = x400Addresses;
    this.directoryNames = directoryNames;
    this.ediPartyNames = ediPartyNames;
    this.uniformResourceIdentifiers = uniformResourceIdentifiers;
    this.ipAddresses = ipAddresses;
    this.registeredIDs = registeredIDs;
  }



  /**
   * Creates a new general names object that is decoded from the provided ASN.1
   * element.
   *
   * @param  element  The ASN.1 element to decode as a general names object.
   *
   * @throws  CertException  If the provided element cannot be decoded as a
   *                         general names element.
   */
  GeneralNames(@NotNull final ASN1Element element)
       throws CertException
  {
    try
    {
      final ASN1Element[] elements = element.decodeAsSequence().elements();
      final ArrayList<ASN1Element> ediPartyList =
           new ArrayList<>(elements.length);
      final ArrayList<ASN1Element> x400AddressList =
           new ArrayList<>(elements.length);
      final ArrayList<DN> directoryNameList = new ArrayList<>(elements.length);
      final ArrayList<InetAddress> ipAddressList =
           new ArrayList<>(elements.length);
      final ArrayList<ObjectPair<OID,ASN1Element>> otherNameList =
           new ArrayList<>(elements.length);
      final ArrayList<OID> registeredIDList =
           new ArrayList<>(elements.length);
      final ArrayList<String> dnsNameList = new ArrayList<>(elements.length);
      final ArrayList<String> rfc822NameList = new ArrayList<>(elements.length);
      final ArrayList<String> uriList = new ArrayList<>(elements.length);

      for (final ASN1Element e : elements)
      {
        switch (e.getType())
        {
          case NAME_TYPE_OTHER_NAME:
            final ASN1Element[] otherNameElements =
                 ASN1Sequence.decodeAsSequence(e).elements();
            final OID otherNameOID =
                 ASN1ObjectIdentifier.decodeAsObjectIdentifier(
                      otherNameElements[0]).getOID();
            final ASN1Element otherNameValue =
                 ASN1Element.decode(otherNameElements[1].getValue());
            otherNameList.add(new ObjectPair<>(otherNameOID, otherNameValue));
            break;
          case NAME_TYPE_RFC_822_NAME:
            rfc822NameList.add(
                 ASN1IA5String.decodeAsIA5String(e).stringValue());
            break;
          case NAME_TYPE_DNS_NAME:
            dnsNameList.add(ASN1IA5String.decodeAsIA5String(e).stringValue());
            break;
          case NAME_TYPE_X400_ADDRESS:
            x400AddressList.add(e);
            break;
          case NAME_TYPE_DIRECTORY_NAME:
            final ASN1Element innerElement = ASN1Element.decode(e.getValue());
            directoryNameList.add(X509Certificate.decodeName(innerElement));
            break;
          case NAME_TYPE_EDI_PARTY_NAME:
            ediPartyList.add(e);
            break;
          case NAME_TYPE_UNIFORM_RESOURCE_IDENTIFIER:
            uriList.add(ASN1IA5String.decodeAsIA5String(e).stringValue());
            break;
          case NAME_TYPE_IP_ADDRESS:
            ipAddressList.add(InetAddress.getByAddress(e.getValue()));
            break;
          case NAME_TYPE_REGISTERED_ID:
            registeredIDList.add(
                 ASN1ObjectIdentifier.decodeAsObjectIdentifier(e).getOID());
            break;
        }
      }

      ediPartyNames = Collections.unmodifiableList(ediPartyList);
      otherNames = Collections.unmodifiableList(otherNameList);
      registeredIDs = Collections.unmodifiableList(registeredIDList);
      x400Addresses = Collections.unmodifiableList(x400AddressList);
      directoryNames = Collections.unmodifiableList(directoryNameList);
      ipAddresses =  Collections.unmodifiableList(ipAddressList);
      dnsNames = Collections.unmodifiableList(dnsNameList);
      rfc822Names = Collections.unmodifiableList(rfc822NameList);
      uniformResourceIdentifiers = Collections.unmodifiableList(uriList);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_GENERAL_NAMES_CANNOT_PARSE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes this general names object to an ASN.1 element for use in a
   * certificate extension.
   *
   * @return  The encoded general names object.
   *
   * @throws  CertException  If a problem is encountered while encoding the
   *                         set of general name values.
   */
  @NotNull()
  ASN1Element encode()
       throws CertException
  {
    try
    {
      final ArrayList<ASN1Element> elements = new ArrayList<>(10);
      for (final ObjectPair<OID,ASN1Element> otherName : otherNames)
      {
        elements.add(new ASN1Sequence(NAME_TYPE_OTHER_NAME,
             new ASN1ObjectIdentifier(otherName.getFirst()),
             new ASN1Element(NAME_TYPE_OTHER_NAME_VALUE,
                  otherName.getSecond().encode())));
      }

      for (final String rfc822Name : rfc822Names)
      {
        elements.add(new ASN1IA5String(NAME_TYPE_RFC_822_NAME, rfc822Name));
      }

      for (final String dnsName : dnsNames)
      {
        elements.add(new ASN1IA5String(NAME_TYPE_DNS_NAME, dnsName));
      }

      for (final ASN1Element x400Address : x400Addresses)
      {
        elements.add(new ASN1Element(NAME_TYPE_X400_ADDRESS,
             x400Address.getValue()));
      }

      for (final DN directoryName : directoryNames)
      {
        elements.add(new ASN1Element(NAME_TYPE_DIRECTORY_NAME,
             X509Certificate.encodeName(directoryName).encode()));
      }

      for (final ASN1Element ediPartyName : ediPartyNames)
      {
        elements.add(new ASN1Element(NAME_TYPE_EDI_PARTY_NAME,
             ediPartyName.getValue()));
      }

      for (final String uri : uniformResourceIdentifiers)
      {
        elements.add(new ASN1IA5String(NAME_TYPE_UNIFORM_RESOURCE_IDENTIFIER,
             uri));
      }

      for (final InetAddress ipAddress : ipAddresses)
      {
        elements.add(new ASN1OctetString(NAME_TYPE_IP_ADDRESS,
             ipAddress.getAddress()));
      }

      for (final OID registeredID : registeredIDs)
      {
        elements.add(new ASN1ObjectIdentifier(NAME_TYPE_REGISTERED_ID,
             registeredID));
      }

      return new ASN1Sequence(elements);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_GENERAL_NAMES_CANNOT_ENCODE.get(toString(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the otherName elements from the extension.
   *
   * @return  The otherName elements from the extension.
   */
  @NotNull()
  public List<ObjectPair<OID,ASN1Element>> getOtherNames()
  {
    return otherNames;
  }



  /**
   * Retrieves the RFC 822 names (email addresses) from the extension.
   *
   * @return  The RFC 822 names from the extension.
   */
  @NotNull()
  public List<String> getRFC822Names()
  {
    return rfc822Names;
  }



  /**
   * Retrieves the DNS names from the extension.
   *
   * @return  The DNS names from the extension.
   */
  @NotNull()
  public List<String> getDNSNames()
  {
    return dnsNames;
  }



  /**
   * Retrieves the x400Address elements from the extension.
   *
   * @return  The x400Address elements from the extension.
   */
  @NotNull()
  public List<ASN1Element> getX400Addresses()
  {
    return x400Addresses;
  }



  /**
   * Retrieves the directory names from the extension.
   *
   * @return  The directory names from the extension.
   */
  @NotNull()
  public List<DN> getDirectoryNames()
  {
    return directoryNames;
  }



  /**
   * Retrieves the ediPartyName elements from the extensions.
   *
   * @return  The ediPartyName elements from the extension.
   */
  @NotNull()
  public List<ASN1Element> getEDIPartyNames()
  {
    return ediPartyNames;
  }



  /**
   * Retrieves the uniform resource identifiers (URIs) from the extension.
   *
   * @return  The URIs from the extension.
   */
  @NotNull()
  public List<String> getUniformResourceIdentifiers()
  {
    return uniformResourceIdentifiers;
  }



  /**
   * Retrieves the IP addresses from the extension.
   *
   * @return  The IP addresses from the extension.
   */
  @NotNull()
  public List<InetAddress> getIPAddresses()
  {
    return ipAddresses;
  }



  /**
   * Retrieves the registeredID elements from the extension.
   *
   * @return  The registeredID elements from the extension.
   */
  @NotNull()
  public List<OID> getRegisteredIDs()
  {
    return registeredIDs;
  }



  /**
   * Retrieves a string representation of this general names element.
   *
   * @return  A string representation of this general names element.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this general names element to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GeneralNames(");

    boolean appended = false;
    if (! dnsNames.isEmpty())
    {
      buffer.append("dnsNames={");

      final Iterator<String> iterator = dnsNames.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
      appended = true;
    }

    if (! ipAddresses.isEmpty())
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("ipAddresses={");

      final Iterator<InetAddress> iterator = ipAddresses.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next().getHostAddress());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
      appended = true;
    }

    if (! rfc822Names.isEmpty())
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("rfc822Names={");

      final Iterator<String> iterator = rfc822Names.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
      appended = true;
    }

    if (! directoryNames.isEmpty())
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("directoryNames={");

      final Iterator<DN> iterator = directoryNames.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
      appended = true;
    }

    if (! uniformResourceIdentifiers.isEmpty())
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("uniformResourceIdentifiers={");

      final Iterator<String> iterator = uniformResourceIdentifiers.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
      appended = true;
    }

    if (! registeredIDs.isEmpty())
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("registeredIDs={");

      final Iterator<OID> iterator = registeredIDs.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
      appended = true;
    }

    if (! otherNames.isEmpty())
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("otherNameCount=");
      buffer.append(otherNames.size());
    }

    if (! x400Addresses.isEmpty())
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("x400AddressCount=");
      buffer.append(x400Addresses.size());
    }

    if (! ediPartyNames.isEmpty())
    {
      if (appended)
      {
        buffer.append(", ");
      }

      buffer.append("ediPartyNameCount=");
      buffer.append(ediPartyNames.size());
    }

    buffer.append(')');
  }
}
