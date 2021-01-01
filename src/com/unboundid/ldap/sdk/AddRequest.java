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
package com.unboundid.ldap.sdk;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Timer;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.ldap.protocol.ProtocolOp;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class implements the processing necessary to perform an LDAPv3 add
 * operation, which creates a new entry in the directory.  An add request
 * contains the DN for the entry and the set of attributes to include.  It may
 * also include a set of controls to send to the server.
 * <BR><BR>
 * The contents of the entry to may be specified as a separate DN and collection
 * of attributes, as an {@link Entry} object, or as a list of the lines that
 * comprise the LDIF representation of the entry to add as described in
 * <A HREF="http://www.ietf.org/rfc/rfc2849.txt">RFC 2849</A>.  For example, the
 * following code demonstrates creating an add request from the LDIF
 * representation of the entry:
 * <PRE>
 *   AddRequest addRequest = new AddRequest(
 *     "dn: dc=example,dc=com",
 *     "objectClass: top",
 *     "objectClass: domain",
 *     "dc: example");
 * </PRE>
 * <BR><BR>
 * {@code AddRequest} objects are mutable and therefore can be altered and
 * re-used for multiple requests.  Note, however, that {@code AddRequest}
 * objects are not threadsafe and therefore a single {@code AddRequest} object
 * instance should not be used to process multiple requests at the same time.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class AddRequest
       extends UpdatableLDAPRequest
       implements ReadOnlyAddRequest, ResponseAcceptor, ProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1320730292848237219L;



  // The queue that will be used to receive response messages from the server.
  @NotNull private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<>();

  // The set of attributes to include in the entry to add.
  @NotNull private ArrayList<Attribute> attributes;

  // The message ID from the last LDAP message sent from this request.
  private int messageID = -1;

  // The DN of the entry to be added.
  @NotNull private String dn;



  /**
   * Creates a new add request with the provided DN and set of attributes.
   *
   * @param  dn          The DN for the entry to add.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in the entry to add.
   *                     It must not be {@code null}.
   */
  public AddRequest(@NotNull final String dn,
                    @NotNull final Attribute... attributes)
  {
    super(null);

    Validator.ensureNotNull(dn, attributes);

    this.dn = dn;

    this.attributes = new ArrayList<>(attributes.length);
    this.attributes.addAll(Arrays.asList(attributes));
  }



  /**
   * Creates a new add request with the provided DN and set of attributes.
   *
   * @param  dn          The DN for the entry to add.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in the entry to add.
   *                     It must not be {@code null}.
   * @param  controls    The set of controls to include in the request.
   */
  public AddRequest(@NotNull final String dn,
                    @NotNull final Attribute[] attributes,
                    @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, attributes);

    this.dn = dn;

    this.attributes = new ArrayList<>(attributes.length);
    this.attributes.addAll(Arrays.asList(attributes));
  }



  /**
   * Creates a new add request with the provided DN and set of attributes.
   *
   * @param  dn          The DN for the entry to add.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in the entry to add.
   *                     It must not be {@code null}.
   */
  public AddRequest(@NotNull final String dn,
                    @NotNull final Collection<Attribute> attributes)
  {
    super(null);

    Validator.ensureNotNull(dn, attributes);

    this.dn         = dn;
    this.attributes = new ArrayList<>(attributes);
  }



  /**
   * Creates a new add request with the provided DN and set of attributes.
   *
   * @param  dn          The DN for the entry to add.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in the entry to add.
   *                     It must not be {@code null}.
   * @param  controls    The set of controls to include in the request.
   */
  public AddRequest(@NotNull final String dn,
                    @NotNull final Collection<Attribute> attributes,
                    @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, attributes);

    this.dn         = dn;
    this.attributes = new ArrayList<>(attributes);
  }



  /**
   * Creates a new add request with the provided DN and set of attributes.
   *
   * @param  dn          The DN for the entry to add.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in the entry to add.
   *                     It must not be {@code null}.
   */
  public AddRequest(@NotNull final DN dn,
                    @NotNull final Attribute... attributes)
  {
    super(null);

    Validator.ensureNotNull(dn, attributes);

    this.dn = dn.toString();

    this.attributes = new ArrayList<>(attributes.length);
    this.attributes.addAll(Arrays.asList(attributes));
  }



  /**
   * Creates a new add request with the provided DN and set of attributes.
   *
   * @param  dn          The DN for the entry to add.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in the entry to add.
   *                     It must not be {@code null}.
   * @param  controls    The set of controls to include in the request.
   */
  public AddRequest(@NotNull final DN dn, @NotNull final Attribute[] attributes,
                    @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, attributes);

    this.dn = dn.toString();

    this.attributes = new ArrayList<>(attributes.length);
    this.attributes.addAll(Arrays.asList(attributes));
  }



  /**
   * Creates a new add request with the provided DN and set of attributes.
   *
   * @param  dn          The DN for the entry to add.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in the entry to add.
   *                     It must not be {@code null}.
   */
  public AddRequest(@NotNull final DN dn,
                    @NotNull final Collection<Attribute> attributes)
  {
    super(null);

    Validator.ensureNotNull(dn, attributes);

    this.dn         = dn.toString();
    this.attributes = new ArrayList<>(attributes);
  }



  /**
   * Creates a new add request with the provided DN and set of attributes.
   *
   * @param  dn          The DN for the entry to add.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes to include in the entry to add.
   *                     It must not be {@code null}.
   * @param  controls    The set of controls to include in the request.
   */
  public AddRequest(@NotNull final DN dn,
                    @NotNull final Collection<Attribute> attributes,
                    @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, attributes);

    this.dn         = dn.toString();
    this.attributes = new ArrayList<>(attributes);
  }



  /**
   * Creates a new add request to add the provided entry.
   *
   * @param  entry  The entry to be added.  It must not be {@code null}.
   */
  public AddRequest(@NotNull final Entry entry)
  {
    super(null);

    Validator.ensureNotNull(entry);

    dn         = entry.getDN();
    attributes = new ArrayList<>(entry.getAttributes());
  }



  /**
   * Creates a new add request to add the provided entry.
   *
   * @param  entry     The entry to be added.  It must not be {@code null}.
   * @param  controls  The set of controls to include in the request.
   */
  public AddRequest(@NotNull final Entry entry,
                    @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(entry);

    dn         = entry.getDN();
    attributes = new ArrayList<>(entry.getAttributes());
  }



  /**
   * Creates a new add request with the provided entry in LDIF form.
   *
   * @param  ldifLines  The lines that comprise the LDIF representation of the
   *                    entry to add.  It must not be {@code null} or empty.  It
   *                    may represent a standard LDIF entry, or it may represent
   *                    an LDIF add change record (optionally including
   *                    controls).
   *
   * @throws  LDIFException  If the provided LDIF data cannot be decoded as an
   *                         entry.
   */
  public AddRequest(@NotNull final String... ldifLines)
         throws LDIFException
  {
    super(null);

    final LDIFChangeRecord changeRecord =
         LDIFReader.decodeChangeRecord(true, ldifLines);
    if (changeRecord instanceof LDIFAddChangeRecord)
    {
      dn = changeRecord.getDN();
      attributes = new ArrayList<>(Arrays.asList(
           ((LDIFAddChangeRecord) changeRecord).getAttributes()));
      setControls(changeRecord.getControls());
    }
    else
    {
      throw new LDIFException(
           ERR_ADD_INAPPROPRIATE_CHANGE_TYPE.get(
                changeRecord.getChangeType().name()),
           0L, true, Arrays.asList(ldifLines), null);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getDN()
  {
    return dn;
  }



  /**
   * Specifies the DN for this add request.
   *
   * @param  dn  The DN for this add request.  It must not be {@code null}.
   */
  public void setDN(@NotNull final String dn)
  {
    Validator.ensureNotNull(dn);

    this.dn = dn;
  }



  /**
   * Specifies the DN for this add request.
   *
   * @param  dn  The DN for this add request.  It must not be {@code null}.
   */
  public void setDN(@NotNull final DN dn)
  {
    Validator.ensureNotNull(dn);

    this.dn = dn.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<Attribute> getAttributes()
  {
    return Collections.unmodifiableList(attributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Attribute getAttribute(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    for (final Attribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        return a;
      }
    }

    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean hasAttribute(@NotNull final String attributeName)
  {
    return (getAttribute(attributeName) != null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean hasAttribute(@NotNull final Attribute attribute)
  {
    Validator.ensureNotNull(attribute);

    final Attribute a = getAttribute(attribute.getName());
    return ((a != null) && attribute.equals(a));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean hasAttributeValue(@NotNull final String attributeName,
                                   @NotNull final String attributeValue)
  {
    Validator.ensureNotNull(attributeName, attributeValue);

    final Attribute a = getAttribute(attributeName);
    return ((a != null) && a.hasValue(attributeValue));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean hasAttributeValue(@NotNull final String attributeName,
                                   @NotNull final String attributeValue,
                                   @NotNull final MatchingRule matchingRule)
  {
    Validator.ensureNotNull(attributeName, attributeValue);

    final Attribute a = getAttribute(attributeName);
    return ((a != null) && a.hasValue(attributeValue, matchingRule));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean hasAttributeValue(@NotNull final String attributeName,
                                   @NotNull final byte[] attributeValue)
  {
    Validator.ensureNotNull(attributeName, attributeValue);

    final Attribute a = getAttribute(attributeName);
    return ((a != null) && a.hasValue(attributeValue));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean hasAttributeValue(@NotNull final String attributeName,
                                   @NotNull final byte[] attributeValue,
                                   @NotNull final MatchingRule matchingRule)
  {
    Validator.ensureNotNull(attributeName, attributeValue);

    final Attribute a = getAttribute(attributeName);
    return ((a != null) && a.hasValue(attributeValue, matchingRule));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean hasObjectClass(@NotNull final String objectClassName)
  {
    return hasAttributeValue("objectClass", objectClassName);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Entry toEntry()
  {
    return new Entry(dn, attributes);
  }



  /**
   * Specifies the set of attributes for this add request.  It must not be
   * {@code null}.
   *
   * @param  attributes  The set of attributes for this add request.
   */
  public void setAttributes(@NotNull final Attribute[] attributes)
  {
    Validator.ensureNotNull(attributes);

    this.attributes.clear();
    this.attributes.addAll(Arrays.asList(attributes));
  }



  /**
   * Specifies the set of attributes for this add request.  It must not be
   * {@code null}.
   *
   * @param  attributes  The set of attributes for this add request.
   */
  public void setAttributes(@NotNull final Collection<Attribute> attributes)
  {
    Validator.ensureNotNull(attributes);

    this.attributes.clear();
    this.attributes.addAll(attributes);
  }



  /**
   * Adds the provided attribute to the entry to add.
   *
   * @param  attribute  The attribute to be added to the entry to add.  It must
   *                    not be {@code null}.
   */
  public void addAttribute(@NotNull final Attribute attribute)
  {
    Validator.ensureNotNull(attribute);

    for (int i=0 ; i < attributes.size(); i++)
    {
      final Attribute a = attributes.get(i);
      if (a.getName().equalsIgnoreCase(attribute.getName()))
      {
        attributes.set(i, Attribute.mergeAttributes(a, attribute));
        return;
      }
    }

    attributes.add(attribute);
  }



  /**
   * Adds the provided attribute to the entry to add.
   *
   * @param  name   The name of the attribute to add.  It must not be
   *                {@code null}.
   * @param  value  The value for the attribute to add.  It must not be
   *                {@code null}.
   */
  public void addAttribute(@NotNull final String name,
                           @NotNull final String value)
  {
    Validator.ensureNotNull(name, value);
    addAttribute(new Attribute(name, value));
  }



  /**
   * Adds the provided attribute to the entry to add.
   *
   * @param  name   The name of the attribute to add.  It must not be
   *                {@code null}.
   * @param  value  The value for the attribute to add.  It must not be
   *                {@code null}.
   */
  public void addAttribute(@NotNull final String name,
                           @NotNull final byte[] value)
  {
    Validator.ensureNotNull(name, value);
    addAttribute(new Attribute(name, value));
  }



  /**
   * Adds the provided attribute to the entry to add.
   *
   * @param  name    The name of the attribute to add.  It must not be
   *                 {@code null}.
   * @param  values  The set of values for the attribute to add.  It must not be
   *                 {@code null}.
   */
  public void addAttribute(@NotNull final String name,
                           @NotNull final String... values)
  {
    Validator.ensureNotNull(name, values);
    addAttribute(new Attribute(name, values));
  }



  /**
   * Adds the provided attribute to the entry to add.
   *
   * @param  name    The name of the attribute to add.  It must not be
   *                 {@code null}.
   * @param  values  The set of values for the attribute to add.  It must not be
   *                 {@code null}.
   */
  public void addAttribute(@NotNull final String name,
                           @NotNull final byte[]... values)
  {
    Validator.ensureNotNull(name, values);
    addAttribute(new Attribute(name, values));
  }



  /**
   * Removes the attribute with the specified name from the entry to add.
   *
   * @param  attributeName  The name of the attribute to remove.  It must not be
   *                        {@code null}.
   *
   * @return  {@code true} if the attribute was removed from this add request,
   *          or {@code false} if the add request did not include the specified
   *          attribute.
   */
  public boolean removeAttribute(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    final Iterator<Attribute> iterator = attributes.iterator();
    while (iterator.hasNext())
    {
      final Attribute a = iterator.next();
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        iterator.remove();
        return true;
      }
    }

    return false;
  }



  /**
   * Removes the specified attribute value from this add request.
   *
   * @param  name   The name of the attribute to remove.  It must not be
   *                {@code null}.
   * @param  value  The value of the attribute to remove.  It must not be
   *                {@code null}.
   *
   * @return  {@code true} if the attribute value was removed from this add
   *          request, or {@code false} if the add request did not include the
   *          specified attribute value.
   */
  public boolean removeAttributeValue(@NotNull final String name,
                                      @NotNull final String value)
  {
    Validator.ensureNotNull(name, value);

    int pos = -1;
    for (int i=0; i < attributes.size(); i++)
    {
      final Attribute a = attributes.get(i);
      if (a.getName().equalsIgnoreCase(name))
      {
        pos = i;
        break;
      }
    }

    if (pos < 0)
    {
      return false;
    }

    final Attribute a = attributes.get(pos);
    final Attribute newAttr =
         Attribute.removeValues(a, new Attribute(name, value));

    if (a.getRawValues().length == newAttr.getRawValues().length)
    {
      return false;
    }

    if (newAttr.getRawValues().length == 0)
    {
      attributes.remove(pos);
    }
    else
    {
      attributes.set(pos, newAttr);
    }

    return true;
  }



  /**
   * Removes the specified attribute value from this add request.
   *
   * @param  name   The name of the attribute to remove.  It must not be
   *                {@code null}.
   * @param  value  The value of the attribute to remove.  It must not be
   *                {@code null}.
   *
   * @return  {@code true} if the attribute value was removed from this add
   *          request, or {@code false} if the add request did not include the
   *          specified attribute value.
   */
  public boolean removeAttribute(@NotNull final String name,
                                 @NotNull final byte[] value)
  {
    Validator.ensureNotNull(name, value);

    int pos = -1;
    for (int i=0; i < attributes.size(); i++)
    {
      final Attribute a = attributes.get(i);
      if (a.getName().equalsIgnoreCase(name))
      {
        pos = i;
        break;
      }
    }

    if (pos < 0)
    {
      return false;
    }

    final Attribute a = attributes.get(pos);
    final Attribute newAttr =
         Attribute.removeValues(a, new Attribute(name, value));

    if (a.getRawValues().length == newAttr.getRawValues().length)
    {
      return false;
    }

    if (newAttr.getRawValues().length == 0)
    {
      attributes.remove(pos);
    }
    else
    {
      attributes.set(pos, newAttr);
    }

    return true;
  }



  /**
   * Replaces the specified attribute in the entry to add.  If no attribute with
   * the given name exists in the add request, it will be added.
   *
   * @param  attribute  The attribute to be replaced in this add request.  It
   *                    must not be {@code null}.
   */
  public void replaceAttribute(@NotNull final Attribute attribute)
  {
    Validator.ensureNotNull(attribute);

    for (int i=0; i < attributes.size(); i++)
    {
      if (attributes.get(i).getName().equalsIgnoreCase(attribute.getName()))
      {
        attributes.set(i, attribute);
        return;
      }
    }

    attributes.add(attribute);
  }



  /**
   * Replaces the specified attribute in the entry to add.  If no attribute with
   * the given name exists in the add request, it will be added.
   *
   * @param  name   The name of the attribute to be replaced.  It must not be
   *                {@code null}.
   * @param  value  The new value for the attribute.  It must not be
   *                {@code null}.
   */
  public void replaceAttribute(@NotNull final String name,
                               @NotNull final String value)
  {
    Validator.ensureNotNull(name, value);

    for (int i=0; i < attributes.size(); i++)
    {
      if (attributes.get(i).getName().equalsIgnoreCase(name))
      {
        attributes.set(i, new Attribute(name, value));
        return;
      }
    }

    attributes.add(new Attribute(name, value));
  }



  /**
   * Replaces the specified attribute in the entry to add.  If no attribute with
   * the given name exists in the add request, it will be added.
   *
   * @param  name   The name of the attribute to be replaced.  It must not be
   *                {@code null}.
   * @param  value  The new value for the attribute.  It must not be
   *                {@code null}.
   */
  public void replaceAttribute(@NotNull final String name,
                               @NotNull final byte[] value)
  {
    Validator.ensureNotNull(name, value);

    for (int i=0; i < attributes.size(); i++)
    {
      if (attributes.get(i).getName().equalsIgnoreCase(name))
      {
        attributes.set(i, new Attribute(name, value));
        return;
      }
    }

    attributes.add(new Attribute(name, value));
  }



  /**
   * Replaces the specified attribute in the entry to add.  If no attribute with
   * the given name exists in the add request, it will be added.
   *
   * @param  name    The name of the attribute to be replaced.  It must not be
   *                 {@code null}.
   * @param  values  The new set of values for the attribute.  It must not be
   *                 {@code null}.
   */
  public void replaceAttribute(@NotNull final String name,
                               @NotNull final String... values)
  {
    Validator.ensureNotNull(name, values);

    for (int i=0; i < attributes.size(); i++)
    {
      if (attributes.get(i).getName().equalsIgnoreCase(name))
      {
        attributes.set(i, new Attribute(name, values));
        return;
      }
    }

    attributes.add(new Attribute(name, values));
  }



  /**
   * Replaces the specified attribute in the entry to add.  If no attribute with
   * the given name exists in the add request, it will be added.
   *
   * @param  name    The name of the attribute to be replaced.  It must not be
   *                 {@code null}.
   * @param  values  The new set of values for the attribute.  It must not be
   *                 {@code null}.
   */
  public void replaceAttribute(@NotNull final String name,
                               @NotNull final byte[]... values)
  {
    Validator.ensureNotNull(name, values);

    for (int i=0; i < attributes.size(); i++)
    {
      if (attributes.get(i).getName().equalsIgnoreCase(name))
      {
        attributes.set(i, new Attribute(name, values));
        return;
      }
    }

    attributes.add(new Attribute(name, values));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeTo(@NotNull final ASN1Buffer buffer)
  {
    final ASN1BufferSequence requestSequence =
         buffer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST);
    buffer.addOctetString(dn);

    final ASN1BufferSequence attrSequence = buffer.beginSequence();
    for (final Attribute a : attributes)
    {
      a.writeTo(buffer);
    }
    attrSequence.end();

    requestSequence.end();
  }



  /**
   * Encodes the add request protocol op to an ASN.1 element.
   *
   * @return  The ASN.1 element with the encoded add request protocol op.
   */
  @Override()
  @NotNull()
  public ASN1Element encodeProtocolOp()
  {
    // Create the add request protocol op.
    final ASN1Element[] attrElements = new ASN1Element[attributes.size()];
    for (int i=0; i < attrElements.length; i++)
    {
      attrElements[i] = attributes.get(i).encode();
    }

    final ASN1Element[] addRequestElements =
    {
      new ASN1OctetString(dn),
      new ASN1Sequence(attrElements)
    };

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST,
                            addRequestElements);
  }



  /**
   * Sends this add request to the directory server over the provided connection
   * and returns the associated response.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   *
   * @return  An LDAP result object that provides information about the result
   *          of the add processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @Override()
  @NotNull()
  protected LDAPResult process(@NotNull final LDAPConnection connection,
                               final int depth)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      @SuppressWarnings("deprecation")
      final boolean autoReconnect =
           connection.getConnectionOptions().autoReconnect();
      return processSync(connection, depth, autoReconnect);
    }

    final long requestTime = System.nanoTime();
    processAsync(connection, null);

    try
    {
      // Wait for and process the response.
      final LDAPResponse response;
      try
      {
        final long responseTimeout = getResponseTimeoutMillis(connection);
        if (responseTimeout > 0)
        {
          response = responseQueue.poll(responseTimeout, TimeUnit.MILLISECONDS);
        }
        else
        {
          response = responseQueue.take();
        }
      }
      catch (final InterruptedException ie)
      {
        Debug.debugException(ie);
        Thread.currentThread().interrupt();
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_ADD_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response, requestTime, depth, false);
    }
    finally
    {
      connection.deregisterResponseAcceptor(messageID);
    }
  }



  /**
   * Sends this add request to the directory server over the provided connection
   * and returns the message ID for the request.
   *
   * @param  connection      The connection to use to communicate with the
   *                         directory server.
   * @param  resultListener  The async result listener that is to be notified
   *                         when the response is received.  It may be
   *                         {@code null} only if the result is to be processed
   *                         by this class.
   *
   * @return  The async request ID created for the operation, or {@code null} if
   *          the provided {@code resultListener} is {@code null} and the
   *          operation will not actually be processed asynchronously.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  @NotNull()
  AsyncRequestID processAsync(@NotNull final LDAPConnection connection,
                      @Nullable final AsyncResultListener resultListener)
                 throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message =
         new LDAPMessage(messageID,  this, getControls());


    // If the provided async result listener is {@code null}, then we'll use
    // this class as the message acceptor.  Otherwise, create an async helper
    // and use it as the message acceptor.
    final AsyncRequestID asyncRequestID;
    final long timeout = getResponseTimeoutMillis(connection);
    if (resultListener == null)
    {
      asyncRequestID = null;
      connection.registerResponseAcceptor(messageID, this);
    }
    else
    {
      final AsyncHelper helper = new AsyncHelper(connection, OperationType.ADD,
           messageID, resultListener, getIntermediateResponseListener());
      connection.registerResponseAcceptor(messageID, helper);
      asyncRequestID = helper.getAsyncRequestID();

      if (timeout > 0L)
      {
        final Timer timer = connection.getTimer();
        final AsyncTimeoutTimerTask timerTask =
             new AsyncTimeoutTimerTask(helper);
        timer.schedule(timerTask, timeout);
        asyncRequestID.setTimerTask(timerTask);
      }
    }


    // Send the request to the server.
    try
    {
      Debug.debugLDAPRequest(Level.INFO, this, messageID, connection);

      final LDAPConnectionLogger logger =
           connection.getConnectionOptions().getConnectionLogger();
      if (logger != null)
      {
        logger.logAddRequest(connection, messageID, this);
      }

      connection.getConnectionStatistics().incrementNumAddRequests();
      connection.sendMessage(message, timeout);
      return asyncRequestID;
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      connection.deregisterResponseAcceptor(messageID);
      throw le;
    }
  }



  /**
   * Processes this add operation in synchronous mode, in which the same thread
   * will send the request and read the response.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   * @param  allowRetry  Indicates whether the request may be re-tried on a
   *                     re-established connection if the initial attempt fails
   *                     in a way that indicates the connection is no longer
   *                     valid and autoReconnect is true.
   *
   * @return  An LDAP result object that provides information about the result
   *          of the add processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @NotNull()
  private LDAPResult processSync(@NotNull final LDAPConnection connection,
                                 final int depth, final boolean allowRetry)
          throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message =
         new LDAPMessage(messageID,  this, getControls());


    // Send the request to the server.
    final long requestTime = System.nanoTime();
    Debug.debugLDAPRequest(Level.INFO, this, messageID, connection);

    final LDAPConnectionLogger logger =
         connection.getConnectionOptions().getConnectionLogger();
    if (logger != null)
    {
      logger.logAddRequest(connection, messageID, this);
    }

    connection.getConnectionStatistics().incrementNumAddRequests();
    try
    {
      connection.sendMessage(message, getResponseTimeoutMillis(connection));
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      if (allowRetry)
      {
        final LDAPResult retryResult = reconnectAndRetry(connection, depth,
             le.getResultCode());
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      throw le;
    }

    while (true)
    {
      final LDAPResponse response;
      try
      {
        response = connection.readResponse(messageID);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        if ((le.getResultCode() == ResultCode.TIMEOUT) &&
            connection.getConnectionOptions().abandonOnTimeout())
        {
          connection.abandon(messageID);
        }

        if (allowRetry)
        {
          final LDAPResult retryResult = reconnectAndRetry(connection, depth,
               le.getResultCode());
          if (retryResult != null)
          {
            return retryResult;
          }
        }

        throw le;
      }

      if (response instanceof IntermediateResponse)
      {
        final IntermediateResponseListener listener =
             getIntermediateResponseListener();
        if (listener != null)
        {
          listener.intermediateResponseReturned(
               (IntermediateResponse) response);
        }
      }
      else
      {
        return handleResponse(connection, response, requestTime, depth,
             allowRetry);
      }
    }
  }



  /**
   * Performs the necessary processing for handling a response.
   *
   * @param  connection   The connection used to read the response.
   * @param  response     The response to be processed.
   * @param  requestTime  The time the request was sent to the server.
   * @param  depth        The current referral depth for this request.  It
   *                      should always be one for the initial request, and
   *                      should only be incremented when following referrals.
   * @param  allowRetry   Indicates whether the request may be re-tried on a
   *                      re-established connection if the initial attempt fails
   *                      in a way that indicates the connection is no longer
   *                      valid and autoReconnect is true.
   *
   * @return  The add result.
   *
   * @throws  LDAPException  If a problem occurs.
   */
  @NotNull()
  private LDAPResult handleResponse(@NotNull final LDAPConnection connection,
                                    @Nullable final LDAPResponse response,
                                    final long requestTime, final int depth,
                                    final boolean allowRetry)
          throws LDAPException
  {
    if (response == null)
    {
      final long waitTime =
           StaticUtils.nanosToMillis(System.nanoTime() - requestTime);
      if (connection.getConnectionOptions().abandonOnTimeout())
      {
        connection.abandon(messageID);
      }

      throw new LDAPException(ResultCode.TIMEOUT,
           ERR_ADD_CLIENT_TIMEOUT.get(waitTime, messageID, dn,
                connection.getHostPort()));
    }

    connection.getConnectionStatistics().incrementNumAddResponses(
         System.nanoTime() - requestTime);

    if (response instanceof ConnectionClosedResponse)
    {
      // The connection was closed while waiting for the response.
      if (allowRetry)
      {
        final LDAPResult retryResult = reconnectAndRetry(connection, depth,
             ResultCode.SERVER_DOWN);
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String message = ccr.getMessage();
      if (message == null)
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_ADD_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_ADD_RESPONSE_WITH_MESSAGE.get(
                  connection.getHostPort(), toString(), message));
      }
    }

    final LDAPResult result = (LDAPResult) response;
    if ((result.getResultCode().equals(ResultCode.REFERRAL)) &&
        followReferrals(connection))
    {
      if (depth >= connection.getConnectionOptions().getReferralHopLimit())
      {
        return new LDAPResult(messageID, ResultCode.REFERRAL_LIMIT_EXCEEDED,
                              ERR_TOO_MANY_REFERRALS.get(),
                              result.getMatchedDN(),
                              result.getReferralURLs(),
                              result.getResponseControls());
      }

      return followReferral(result, connection, depth);
    }
    else
    {
      if (allowRetry)
      {
        final LDAPResult retryResult = reconnectAndRetry(connection, depth,
             result.getResultCode());
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      return result;
    }
  }



  /**
   * Attempts to re-establish the connection and retry processing this request
   * on it.
   *
   * @param  connection  The connection to be re-established.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   * @param  resultCode  The result code for the previous operation attempt.
   *
   * @return  The result from re-trying the add, or {@code null} if it could not
   *          be re-tried.
   */
  @Nullable()
  private LDAPResult reconnectAndRetry(@NotNull final LDAPConnection connection,
                                       final int depth,
                                       @NotNull final ResultCode resultCode)
  {
    try
    {
      // We will only want to retry for certain result codes that indicate a
      // connection problem.
      switch (resultCode.intValue())
      {
        case ResultCode.SERVER_DOWN_INT_VALUE:
        case ResultCode.DECODING_ERROR_INT_VALUE:
        case ResultCode.CONNECT_ERROR_INT_VALUE:
          connection.reconnect();
          return processSync(connection, depth, false);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    return null;
  }



  /**
   * Attempts to follow a referral to perform an add operation in the target
   * server.
   *
   * @param  referralResult  The LDAP result object containing information about
   *                         the referral to follow.
   * @param  connection      The connection on which the referral was received.
   * @param  depth           The number of referrals followed in the course of
   *                         processing this request.
   *
   * @return  The result of attempting to process the add operation by following
   *          the referral.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         the referral connection, sending the request, or
   *                         reading the result.
   */
  @NotNull()
  private LDAPResult followReferral(@NotNull final LDAPResult referralResult,
                                    @NotNull final LDAPConnection connection,
                                    final int depth)
          throws LDAPException
  {
    for (final String urlString : referralResult.getReferralURLs())
    {
      try
      {
        final LDAPURL referralURL = new LDAPURL(urlString);
        final String host = referralURL.getHost();

        if (host == null)
        {
          // We can't handle a referral in which there is no host.
          continue;
        }

        final AddRequest addRequest;
        if (referralURL.baseDNProvided())
        {
          addRequest = new AddRequest(referralURL.getBaseDN(), attributes,
                                      getControls());
        }
        else
        {
          addRequest = this;
        }

        final LDAPConnection referralConn = getReferralConnector(connection).
             getReferralConnection(referralURL, connection);
        try
        {
          return addRequest.process(referralConn, (depth+1));
        }
        finally
        {
          referralConn.setDisconnectInfo(DisconnectType.REFERRAL, null, null);
          referralConn.close();
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
      }
    }

    // If we've gotten here, then we could not follow any of the referral URLs,
    // so we'll just return the original referral result.
    return referralResult;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public OperationType getOperationType()
  {
    return OperationType.ADD;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AddRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AddRequest duplicate(@Nullable final Control[] controls)
  {
    final ArrayList<Attribute> attrs = new ArrayList<>(attributes);
    final AddRequest r = new AddRequest(dn, attrs, controls);

    if (followReferralsInternal() != null)
    {
      r.setFollowReferrals(followReferralsInternal());
    }

    if (getReferralConnectorInternal() != null)
    {
      r.setReferralConnector(getReferralConnectorInternal());
    }

    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));

    return r;
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void responseReceived(@NotNull final LDAPResponse response)
         throws LDAPException
  {
    try
    {
      responseQueue.put(response);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (e instanceof InterruptedException)
      {
        Thread.currentThread().interrupt();
      }

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_EXCEPTION_HANDLING_RESPONSE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDIFAddChangeRecord toLDIFChangeRecord()
  {
    return new LDIFAddChangeRecord(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String[] toLDIF()
  {
    return toLDIFChangeRecord().toLDIF();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String toLDIFString()
  {
    return toLDIFChangeRecord().toLDIFString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AddRequest(dn='");
    buffer.append(dn);
    buffer.append("', attrs={");

    for (int i=0; i < attributes.size(); i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append(attributes.get(i));
    }
    buffer.append('}');

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toCode(@NotNull final List<String> lineList,
                     @NotNull final String requestID,
                     final int indentSpaces, final boolean includeProcessing)
  {
    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs =
         new ArrayList<>(attributes.size() + 1);
    constructorArgs.add(ToCodeArgHelper.createString(dn, "Entry DN"));

    boolean firstAttribute = true;
    for (final Attribute a : attributes)
    {
      final String comment;
      if (firstAttribute)
      {
        firstAttribute = false;
        comment = "Entry Attributes";
      }
      else
      {
        comment = null;
      }

      constructorArgs.add(ToCodeArgHelper.createAttribute(a, comment));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, "AddRequest",
         requestID + "Request", "new AddRequest", constructorArgs);


    // If there are any controls, then add them to the request.
    for (final Control c : getControls())
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "Request.addControl",
           ToCodeArgHelper.createControl(c, null));
    }


    // Add lines for processing the request and obtaining the result.
    if (includeProcessing)
    {
      // Generate a string with the appropriate indent.
      final StringBuilder buffer = new StringBuilder();
      for (int i=0; i < indentSpaces; i++)
      {
        buffer.append(' ');
      }
      final String indent = buffer.toString();

      lineList.add("");
      lineList.add(indent + "try");
      lineList.add(indent + '{');
      lineList.add(indent + "  LDAPResult " + requestID +
           "Result = connection.add(" + requestID + "Request);");
      lineList.add(indent + "  // The add was processed successfully.");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (LDAPException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // The add failed.  Maybe the following will " +
           "help explain why.");
      lineList.add(indent + "  ResultCode resultCode = e.getResultCode();");
      lineList.add(indent + "  String message = e.getMessage();");
      lineList.add(indent + "  String matchedDN = e.getMatchedDN();");
      lineList.add(indent + "  String[] referralURLs = e.getReferralURLs();");
      lineList.add(indent + "  Control[] responseControls = " +
           "e.getResponseControls();");
      lineList.add(indent + '}');
    }
  }
}
