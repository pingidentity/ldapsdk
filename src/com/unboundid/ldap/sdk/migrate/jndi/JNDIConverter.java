/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.jndi;



import java.util.Collection;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.BasicControl;
import javax.naming.ldap.ExtendedResponse;

import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This utility class provides a set of methods that may be used to convert
 * between data structures in the Java Naming and Directory Interface (JNDI)
 * and the corresponding data structures in the UnboundID LDAP SDK for Java.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JNDIConverter
{
  /**
   * An empty array of attributes.
   */
  @NotNull private static final Attribute[] NO_ATTRIBUTES = new Attribute[0];



  /**
   * An empty array of JNDI controls.
   */
  @NotNull private static final javax.naming.ldap.Control[] NO_JNDI_CONTROLS =
       new javax.naming.ldap.Control[0];



  /**
   * An empty array of SDK modifications.
   */
  @NotNull private static final Modification[] NO_MODIFICATIONS =
       new Modification[0];



  /**
   * An empty array of JNDI modification items.
   */
  @NotNull private static final ModificationItem[] NO_MODIFICATION_ITEMS =
       new ModificationItem[0];



  /**
   * An empty array of SDK controls.
   */
  @NotNull private static final Control[] NO_SDK_CONTROLS = new Control[0];



  /**
   * Prevent this utility class from being instantiated.
   */
  private JNDIConverter()
  {
    // No implementation required.
  }



  /**
   * Converts the provided JNDI attribute to an LDAP SDK attribute.
   *
   * @param  a  The attribute to be converted.
   *
   * @return  The LDAP SDK attribute that corresponds to the provided JNDI
   *          attribute.
   *
   * @throws  NamingException  If a problem is encountered during the conversion
   *                           process.
   */
  @Nullable()
  public static Attribute convertAttribute(
                     @Nullable final javax.naming.directory.Attribute a)
         throws NamingException
  {
    if (a == null)
    {
      return null;
    }

    final String name = a.getID();
    final ASN1OctetString[] values = new ASN1OctetString[a.size()];

    for (int i=0; i < values.length; i++)
    {
      final Object value = a.get(i);
      if (value instanceof byte[])
      {
        values[i] = new ASN1OctetString((byte[]) value);
      }
      else
      {
        values[i] = new ASN1OctetString(String.valueOf(value));
      }
    }

    return new Attribute(name, values);
  }



  /**
   * Converts the provided LDAP SDK attribute to a JNDI attribute.
   *
   * @param  a  The attribute to be converted.
   *
   * @return  The JNDI attribute that corresponds to the provided LDAP SDK
   *          attribute.
   */
  @Nullable()
  public static javax.naming.directory.Attribute convertAttribute(
                     @Nullable final Attribute a)
  {
    if (a == null)
    {
      return null;
    }

    final BasicAttribute attr = new BasicAttribute(a.getName(), true);
    for (final String v : a.getValues())
    {
      attr.add(v);
    }

    return attr;
  }



  /**
   * Converts the provided JNDI attributes to an array of LDAP SDK attributes.
   *
   * @param  a  The attributes to be converted.
   *
   * @return  The array of LDAP SDK attributes that corresponds to the
   *          provided JNDI attributes.
   *
   * @throws  NamingException  If a problem is encountered during the conversion
   *                           process.
   */
  @NotNull()
  public static Attribute[] convertAttributes(@Nullable final Attributes a)
         throws NamingException
  {
    if (a == null)
    {
      return NO_ATTRIBUTES;
    }

    int i=0;
    final Attribute[] attributes = new Attribute[a.size()];
    final NamingEnumeration<? extends javax.naming.directory.Attribute> e =
         a.getAll();

    try
    {
      while (e.hasMoreElements())
      {
        attributes[i++] = convertAttribute(e.next());
      }
    }
    finally
    {
      e.close();
    }

    return attributes;
  }



  /**
   * Converts the provided array of LDAP SDK attributes to a set of JNDI
   * attributes.
   *
   * @param  a  The array of attributes to be converted.
   *
   * @return  The JNDI attributes that corresponds to the provided LDAP SDK
   *          attributes.
   */
  @NotNull()
  public static Attributes convertAttributes(@Nullable final Attribute... a)
  {
    final BasicAttributes attrs = new BasicAttributes(true);
    if (a == null)
    {
      return attrs;
    }

    for (final Attribute attr : a)
    {
      attrs.put(convertAttribute(attr));
    }

    return attrs;
  }



  /**
   * Converts the provided collection of LDAP SDK attributes to a set of JNDI
   * attributes.
   *
   * @param  a  The collection of attributes to be converted.
   *
   * @return  The JNDI attributes that corresponds to the provided LDAP SDK
   *          attributes.
   */
  @NotNull()
  public static Attributes convertAttributes(
                                @Nullable final Collection<Attribute> a)
  {
    final BasicAttributes attrs = new BasicAttributes(true);
    if (a == null)
    {
      return attrs;
    }

    for (final Attribute attr : a)
    {
      attrs.put(convertAttribute(attr));
    }

    return attrs;
  }



  /**
   * Converts the provided JNDI control to an LDAP SDK control.
   *
   * @param  c  The control to be converted.
   *
   * @return  The LDAP SDK control that corresponds to the provided JNDI
   *          control.
   *
   * @throws  NamingException  If a problem is encountered during the conversion
   *                           process.
   */
  @Nullable
  public static Control convertControl(
                             @Nullable final javax.naming.ldap.Control c)
         throws NamingException
  {
    if (c == null)
    {
      return null;
    }

    final ASN1OctetString value;
    final byte[] valueBytes = c.getEncodedValue();
    if ((valueBytes == null) || (valueBytes.length == 0))
    {
      value = null;
    }
    else
    {
      try
      {
        value = ASN1OctetString.decodeAsOctetString(valueBytes);
      }
      catch (final ASN1Exception ae)
      {
        throw new NamingException(StaticUtils.getExceptionMessage(ae));
      }
    }

    return new Control(c.getID(), c.isCritical(), value);
  }



  /**
   * Converts the provided LDAP SDK control to a JNDI control.
   *
   * @param  c  The control to be converted.
   *
   * @return  The JNDI control that corresponds to the provided LDAP SDK
   *          control.
   */
  @Nullable()
  public static javax.naming.ldap.Control convertControl(
                                               @Nullable final Control c)
  {
    if (c == null)
    {
      return null;
    }

    final ASN1OctetString value = c.getValue();
    if (value == null)
    {
      return new BasicControl(c.getOID(), c.isCritical(), null);
    }
    else
    {
      return new BasicControl(c.getOID(), c.isCritical(), value.encode());
    }
  }



  /**
   * Converts the provided array of JNDI controls to an array of LDAP SDK
   * controls.
   *
   * @param  c  The array of JNDI controls to be converted.
   *
   * @return  The array of LDAP SDK controls that corresponds to the provided
   *          array of JNDI controls.
   *
   * @throws  NamingException  If a problem is encountered during the conversion
   *                           process.
   */
  @NotNull()
  public static Control[] convertControls(
                               @Nullable final javax.naming.ldap.Control... c)
         throws NamingException
  {
    if (c == null)
    {
      return NO_SDK_CONTROLS;
    }

    final Control[] controls = new Control[c.length];
    for (int i=0; i < controls.length; i++)
    {
      controls[i] = convertControl(c[i]);
    }

    return controls;
  }



  /**
   * Converts the provided array of LDAP SDK controls to an array of JNDI
   * controls.
   *
   * @param  c  The array of LDAP SDK controls to be converted.
   *
   * @return  The array of JNDI controls that corresponds to the provided array
   *          of LDAP SDK controls.
   */
  @NotNull()
  public static javax.naming.ldap.Control[] convertControls(
                                                 @Nullable final Control... c)
  {
    if (c == null)
    {
      return NO_JNDI_CONTROLS;
    }

    final javax.naming.ldap.Control[] controls =
         new javax.naming.ldap.Control[c.length];
    for (int i=0; i < controls.length; i++)
    {
      controls[i] = convertControl(c[i]);
    }

    return controls;
  }



  /**
   * Converts the provided JNDI extended request to an LDAP SDK extended
   * request.
   *
   * @param  r  The request to be converted.
   *
   * @return  The LDAP SDK extended request that corresponds to the provided
   *          JNDI extended request.
   *
   * @throws  NamingException  If a problem is encountered during the conversion
   *                           process.
   */
  @Nullable()
  public static ExtendedRequest convertExtendedRequest(
                     @Nullable final javax.naming.ldap.ExtendedRequest r)
         throws NamingException
  {
    if (r == null)
    {
      return null;
    }

    return JNDIExtendedRequest.toSDKExtendedRequest(r);
  }



  /**
   * Converts the provided LDAP SDK extended request to a JNDI extended request.
   *
   * @param  r  The request to be converted.
   *
   * @return  The JNDI extended request that corresponds to the provided LDAP
   *          SDK extended request.
   */
  @Nullable()
  public static javax.naming.ldap.ExtendedRequest convertExtendedRequest(
                     @Nullable final ExtendedRequest r)
  {
    if (r == null)
    {
      return null;
    }

    return new JNDIExtendedRequest(r);
  }



  /**
   * Converts the provided JNDI extended response to an LDAP SDK extended
   * result.
   *
   * @param  r  The response to be converted.
   *
   * @return  The LDAP SDK extended result that corresponds to the provided
   *          JNDI extended response.
   *
   * @throws  NamingException  If a problem is encountered during the conversion
   *                           process.
   */
  @Nullable()
  public static ExtendedResult convertExtendedResponse(
                                    @Nullable final ExtendedResponse r)
         throws NamingException
  {
    if (r == null)
    {
      return null;
    }

    return JNDIExtendedResponse.toSDKExtendedResult(r);
  }



  /**
   * Converts the provided LDAP SDK extended result to a JNDI extended response.
   *
   * @param  r  The result to be converted.
   *
   * @return  The JNDI extended response that corresponds to the provided LDAP
   *          SDK extended result.
   */
  @Nullable()
  public static ExtendedResponse convertExtendedResult(
                                      @Nullable final ExtendedResult r)
  {
    if (r == null)
    {
      return null;
    }

    return new JNDIExtendedResponse(r);
  }



  /**
   * Converts the provided JNDI modification item to an LDAP SDK modification.
   *
   * @param  m  The JNDI modification item to be converted.
   *
   * @return  The LDAP SDK modification that corresponds to the provided JNDI
   *          modification item.
   *
   * @throws  NamingException  If a problem is encountered during the conversion
   *                           process.
   */
  @Nullable()
  public static Modification convertModification(
                                  @Nullable final ModificationItem m)
         throws NamingException
  {
    if (m == null)
    {
      return null;
    }

    final ModificationType modType;
    switch (m.getModificationOp())
    {
      case DirContext.ADD_ATTRIBUTE:
        modType = ModificationType.ADD;
        break;
      case DirContext.REMOVE_ATTRIBUTE:
        modType = ModificationType.DELETE;
        break;
      case DirContext.REPLACE_ATTRIBUTE:
        modType = ModificationType.REPLACE;
        break;
      default:
        throw new NamingException("Unsupported modification type " + m);
    }

    final Attribute a = convertAttribute(m.getAttribute());

    return new Modification(modType, a.getName(), a.getRawValues());
  }



  /**
   * Converts the provided LDAP SDK modification to a JNDI modification item.
   *
   * @param  m  The LDAP SDK modification to be converted.
   *
   * @return  The JNDI modification item that corresponds to the provided LDAP
   *          SDK modification.
   *
   * @throws  NamingException  If a problem is encountered during the conversion
   *                           process.
   */
  @Nullable()
  public static ModificationItem convertModification(
                                      @Nullable final Modification m)
         throws NamingException
  {
    if (m == null)
    {
      return null;
    }

    final int modType;
    switch (m.getModificationType().intValue())
    {
      case ModificationType.ADD_INT_VALUE:
        modType = DirContext.ADD_ATTRIBUTE;
        break;
      case ModificationType.DELETE_INT_VALUE:
        modType = DirContext.REMOVE_ATTRIBUTE;
        break;
      case ModificationType.REPLACE_INT_VALUE:
        modType = DirContext.REPLACE_ATTRIBUTE;
        break;
      default:
        throw new NamingException("Unsupported modification type " + m);
    }

    return new ModificationItem(modType, convertAttribute(m.getAttribute()));
  }



  /**
   * Converts the provided array of JNDI modification items to an array of LDAP
   * SDK modifications.
   *
   * @param  m  The array of JNDI modification items to be converted.
   *
   * @return  The array of LDAP SDK modifications that corresponds to the
   *          provided array of JNDI modification items.
   *
   * @throws  NamingException  If a problem is encountered during the conversion
   *                           process.
   */
  @NotNull()
  public static Modification[] convertModifications(
                                    @Nullable final ModificationItem... m)
         throws NamingException
  {
    if (m == null)
    {
      return NO_MODIFICATIONS;
    }

    final Modification[] mods = new Modification[m.length];
    for (int i=0; i < m.length; i++)
    {
      mods[i] = convertModification(m[i]);
    }

    return mods;
  }



  /**
   * Converts the provided array of LDAP SDK modifications to an array of JNDI
   * modification items.
   *
   * @param  m  The array of LDAP SDK modifications to be converted.
   *
   * @return  The array of JNDI modification items that corresponds to the
   *          provided array of LDAP SDK modifications.
   *
   * @throws  NamingException  If a problem is encountered during the conversion
   *                           process.
   */
  @NotNull()
  public static ModificationItem[] convertModifications(
                                        @Nullable final Modification... m)
         throws NamingException
  {
    if (m == null)
    {
      return NO_MODIFICATION_ITEMS;
    }

    final ModificationItem[] mods = new ModificationItem[m.length];
    for (int i=0; i < m.length; i++)
    {
      mods[i] = convertModification(m[i]);
    }

    return mods;
  }



  /**
   * Converts the provided JNDI search result object to an LDAP SDK entry.
   *
   * @param  r  The JNDI search result object to be converted.
   *
   * @return  The LDAP SDK entry that corresponds to the provided JNDI search
   *          result.
   *
   * @throws  NamingException  If a problem is encountered during the conversion
   *                           process.
   */
  @Nullable()
  public static Entry convertSearchEntry(@Nullable final SearchResult r)
         throws NamingException
  {
    return convertSearchEntry(r, null);
  }



  /**
   * Converts the provided JNDI search result object to an LDAP SDK entry.
   *
   * @param  r              The JNDI search result object to be converted.
   * @param  contextBaseDN  The base DN for the JNDI context over which the
   *                        search result was retrieved.  If it is
   *                        non-{@code null} and non-empty, then it will be
   *                        appended to the result of the {@code getName} method
   *                        to obtain the entry's full DN.
   *
   * @return  The LDAP SDK entry that corresponds to the provided JNDI search
   *          result.
   *
   * @throws  NamingException  If a problem is encountered during the conversion
   *                           process.
   */
  @Nullable
  public static Entry convertSearchEntry(@Nullable final SearchResult r,
                                         @Nullable final String contextBaseDN)
         throws NamingException
  {
    if (r == null)
    {
      return null;
    }

    final String dn;
    if ((contextBaseDN == null) || contextBaseDN.isEmpty())
    {
      dn = r.getName();
    }
    else
    {
      final String name = r.getName();
      if ((name == null) || name.isEmpty())
      {
        dn = contextBaseDN;
      }
      else
      {
        dn = r.getName() + ',' + contextBaseDN;
      }
    }

    return new Entry(dn, convertAttributes(r.getAttributes()));
  }



  /**
   * Converts the provided LDAP SDK entry to a JNDI search result.
   *
   * @param  e  The entry to be converted to a JNDI search result.
   *
   * @return  The JNDI search result that corresponds to the provided LDAP SDK
   *          entry.
   */
  @Nullable()
  public static SearchResult convertSearchEntry(@Nullable final Entry e)
  {
    return convertSearchEntry(e, null);
  }



  /**
   * Converts the provided LDAP SDK entry to a JNDI search result.
   *
   * @param  e              The entry to be converted to a JNDI search result.
   * @param  contextBaseDN  The base DN for the JNDI context over which the
   *                        search result was retrieved.  If it is
   *                        non-{@code null} and non-empty, then it will be
   *                        removed from the end of the entry's DN in order to
   *                        obtain the name for the {@code SearchResult} that is
   *                        returned.
   *
   * @return  The JNDI search result that corresponds to the provided LDAP SDK
   *          entry.
   */
  @Nullable()
  public static SearchResult convertSearchEntry(@Nullable final Entry e,
                                  @Nullable final String contextBaseDN)
  {
    if (e == null)
    {
      return null;
    }

    String name = e.getDN();
    if ((contextBaseDN != null) && (! contextBaseDN.isEmpty()))
    {
      try
      {
        final DN parsedEntryDN = e.getParsedDN();
        final DN parsedBaseDN = new DN(contextBaseDN);
        if (parsedEntryDN.equals(parsedBaseDN))
        {
          name = "";
        }
        else if (parsedEntryDN.isDescendantOf(parsedBaseDN, false))
        {
          final RDN[] entryRDNs = parsedEntryDN.getRDNs();
          final RDN[] baseRDNs = parsedBaseDN.getRDNs();
          final RDN[] remainingRDNs =
               new RDN[entryRDNs.length - baseRDNs.length];
          System.arraycopy(entryRDNs, 0, remainingRDNs, 0,
               remainingRDNs.length);
          name = new DN(remainingRDNs).toString();
        }
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
      }
    }

    final Collection<Attribute> attrs = e.getAttributes();
    final Attribute[] attributes = new Attribute[attrs.size()];
    attrs.toArray(attributes);

    return new SearchResult(name, null, convertAttributes(attributes));
  }
}
