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



import java.net.InetAddress;
import java.util.Iterator;
import java.util.List;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides support for decoding the values of the
 * {@link SubjectAlternativeNameExtension} and
 * {@link IssuerAlternativeNameExtension} extensions as described in
 * <A HREF="https://www.ietf.org/rfc/rfc5280.txt">RFC 5280</A> sections 4.2.1.6
 * and 4.2.1.7.
 * <BR><BR>
 * Note that this implementation only provides complete decoding for the RFC 822
 * names (email addresses), DNS names, directory names, uniform resource
 * identifiers, and IP addresses elements.  The other elements will be left in
 * their raw forms.
 * <BR><BR>
 * The value has the following encoding:
 * <PRE>
 *   SubjectAltName ::= GeneralNames
 *
 *   IssuerAltName ::= GeneralNames
 *
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
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public abstract class GeneralAlternativeNameExtension
       extends X509CertificateExtension
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1076071031835517176L;



  // The general names for inclusion in this extension.
  @NotNull private final GeneralNames generalNames;



  /**
   * Creates a new general alternative name extension with the provided
   * information.
   *
   * @param  oid           The OID for this extension.
   * @param  isCritical    Indicates whether this extension should be
   *                       considered critical.
   * @param  generalNames  The general names for inclusion in this extension.
   *
   * @throws  CertException  If a problem is encountered while encoding the
   *                         value for this extension.
   */
  protected GeneralAlternativeNameExtension(@NotNull final OID oid,
                 final boolean isCritical,
                 @NotNull final GeneralNames generalNames)
       throws CertException
  {
    super(oid, isCritical, generalNames.encode().encode());

    this.generalNames = generalNames;
  }



  /**
   * Creates a new general alternative name extension from the provided generic
   * extension.
   *
   * @param  extension  The extension to decode as a general alternative name
   *                    extension.
   *
   * @throws  CertException  If the provided extension cannot be decoded as a
   *                         general alternative name extension.
   */
  protected GeneralAlternativeNameExtension(
                 @NotNull final X509CertificateExtension extension)
            throws CertException
  {
    super(extension);

    try
    {
      generalNames = new GeneralNames(ASN1Element.decode(extension.getValue()));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      final String name;
      if (extension.getOID().equals(SubjectAlternativeNameExtension.
           SUBJECT_ALTERNATIVE_NAME_OID))
      {
        name = INFO_SUBJECT_ALT_NAME_EXTENSION_NAME.get();
      }
      else if (extension.getOID().equals(IssuerAlternativeNameExtension.
           ISSUER_ALTERNATIVE_NAME_OID))
      {
        name = INFO_ISSUER_ALT_NAME_EXTENSION_NAME.get();
      }
      else
      {
        name = extension.getOID().toString();
      }

      throw new CertException(
           ERR_GENERAL_ALT_NAME_EXTENSION_CANNOT_PARSE.get(
                String.valueOf(extension), name,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the {@code GeneralNames} object for this alternative name
   * extension.
   *
   * @return  The {@code GeneralNames} object for this alternative name
   *          extension.
   */
  @NotNull()
  public final GeneralNames getGeneralNames()
  {
    return generalNames;
  }



  /**
   * Retrieves the otherName elements from the extension.
   *
   * @return  The otherName elements from the extension.
   */
  @NotNull()
  public final List<ObjectPair<OID,ASN1Element>> getOtherNames()
  {
    return generalNames.getOtherNames();
  }



  /**
   * Retrieves the RFC 822 names (email addresses) from the extension.
   *
   * @return  The RFC 822 names from the extension.
   */
  @NotNull()
  public final List<String> getRFC822Names()
  {
    return generalNames.getRFC822Names();
  }



  /**
   * Retrieves the DNS names from the extension.
   *
   * @return  The DNS names from the extension.
   */
  @NotNull()
  public final List<String> getDNSNames()
  {
    return generalNames.getDNSNames();
  }



  /**
   * Retrieves the x400Address elements from the extension.
   *
   * @return  The x400Address elements from the extension.
   */
  @NotNull()
  public final List<ASN1Element> getX400Addresses()
  {
    return generalNames.getX400Addresses();
  }



  /**
   * Retrieves the directory names from the extension.
   *
   * @return  The directory names from the extension.
   */
  @NotNull()
  public final List<DN> getDirectoryNames()
  {
    return generalNames.getDirectoryNames();
  }



  /**
   * Retrieves the ediPartyName elements from the extensions.
   *
   * @return  The ediPartyName elements from the extension.
   */
  @NotNull()
  public final List<ASN1Element> getEDIPartyNames()
  {
    return generalNames.getEDIPartyNames();
  }



  /**
   * Retrieves the uniform resource identifiers (URIs) from the extension.
   *
   * @return  The URIs from the extension.
   */
  @NotNull()
  public final List<String> getUniformResourceIdentifiers()
  {
    return generalNames.getUniformResourceIdentifiers();
  }



  /**
   * Retrieves the IP addresses from the extension.
   *
   * @return  The IP addresses from the extension.
   */
  @NotNull()
  public final List<InetAddress> getIPAddresses()
  {
    return generalNames.getIPAddresses();
  }



  /**
   * Retrieves the registeredID elements from the extension.
   *
   * @return  The registeredID elements from the extension.
   */
  @NotNull()
  public final List<OID> getRegisteredIDs()
  {
    return generalNames.getRegisteredIDs();
  }



  /**
   * Appends a string representation of this extension to the provided buffer.
   *
   * @param  extensionName  The name to use for this extension.
   * @param  buffer         The buffer to which the information should be
   *                        appended.
   */
  protected void toString(@NotNull final String extensionName,
                          @NotNull final StringBuilder buffer)
  {
    buffer.append(extensionName);
    buffer.append("(oid='");
    buffer.append(getOID());
    buffer.append("', isCritical=");
    buffer.append(isCritical());

    if (! getDNSNames().isEmpty())
    {
      buffer.append(", dnsNames={");

      final Iterator<String> iterator = getDNSNames().iterator();
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
    }

    if (! getIPAddresses().isEmpty())
    {
      buffer.append(", ipAddresses={");

      final Iterator<InetAddress> iterator = getIPAddresses().iterator();
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
    }

    if (! getRFC822Names().isEmpty())
    {
      buffer.append(", rfc822Names={");

      final Iterator<String> iterator = getRFC822Names().iterator();
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
    }

    if (! getDirectoryNames().isEmpty())
    {
      buffer.append(", directoryNames={");

      final Iterator<DN> iterator = getDirectoryNames().iterator();
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
    }

    if (! getUniformResourceIdentifiers().isEmpty())
    {
      buffer.append(", uniformResourceIdentifiers={");

      final Iterator<String> iterator =
           getUniformResourceIdentifiers().iterator();
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
    }

    if (! getRegisteredIDs().isEmpty())
    {
      buffer.append(", registeredIDs={");

      final Iterator<OID> iterator = getRegisteredIDs().iterator();
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
    }

    if (! getOtherNames().isEmpty())
    {
      buffer.append(", otherNameCount=");
      buffer.append(getOtherNames().size());
    }

    if (! getX400Addresses().isEmpty())
    {
      buffer.append(", x400AddressCount=");
      buffer.append(getX400Addresses().size());
    }

    if (! getEDIPartyNames().isEmpty())
    {
      buffer.append(", ediPartyNameCount=");
      buffer.append(getEDIPartyNames().size());
    }

    buffer.append(')');
  }
}
