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



import java.util.List;

import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a set of methods that may be safely called in an LDAP
 * add request without altering its contents.  This interface must not be
 * implemented by any class other than {@link AddRequest}.
 * <BR><BR>
 * This interface does not inherently provide the assurance of thread safety for
 * the methods that it exposes, because it is still possible for a thread
 * referencing the object which implements this interface to alter the request
 * using methods not included in this interface.  However, if it can be
 * guaranteed that no thread will alter the underlying object, then the methods
 * exposed by this interface can be safely invoked concurrently by any number of
 * threads.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ReadOnlyAddRequest
       extends ReadOnlyLDAPRequest
{
  /**
   * Retrieves the DN for this add request.
   *
   * @return  The DN for this add request.
   */
  @NotNull()
  String getDN();



  /**
   * Retrieves the set of attributes for this add request.
   *
   * @return  The set of attributes for this add request.
   */
  @NotNull()
  List<Attribute> getAttributes();



  /**
   * Retrieves the specified attribute from this add request.
   *
   * @param  attributeName  The name of the attribute to retrieve.  It must not
   *                        be {@code null}.
   *
   * @return  The requested attribute, or {@code null} if it does not exist in
   *          the add request.
   */
  @Nullable()
  Attribute getAttribute(@NotNull String attributeName);



  /**
   * Indicates whether this add request contains the specified attribute.
   *
   * @param  attributeName  The name of the attribute for which to make the
   *                        determination.  It must not be {@code null}.
   *
   * @return  {@code true} if this add request contains the specified attribute,
   *          or {@code false} if not.
   */
  boolean hasAttribute(@NotNull String attributeName);



  /**
   * Indicates whether this add request contains the specified attribute.  It
   * will only return {@code true} if this add request contains an attribute
   * with the same name and exact set of values.
   *
   * @param  attribute  The attribute for which to make the determination.  It
   *                    must not be {@code null}.
   *
   * @return  {@code true} if this add request contains the specified attribute,
   *          or {@code false} if not.
   */
  boolean hasAttribute(@NotNull Attribute attribute);



  /**
   * Indicates whether this add request contains an attribute with the given
   * name and value.
   *
   * @param  attributeName   The name of the attribute for which to make the
   *                         determination.  It must not be {@code null}.
   * @param  attributeValue  The value for which to make the determination.  It
   *                         must not be {@code null}.
   *
   * @return  {@code true} if this add request contains an attribute with the
   *          specified name and value, or {@code false} if not.
   */
  boolean hasAttributeValue(@NotNull String attributeName,
                            @NotNull String attributeValue);



  /**
   * Indicates whether this add request contains an attribute with the given
   * name and value.
   *
   * @param  attributeName   The name of the attribute for which to make the
   *                         determination.  It must not be {@code null}.
   * @param  attributeValue  The value for which to make the determination.  It
   *                         must not be {@code null}.
   * @param  matchingRule    The matching rule to use to make the determination.
   *                         It must not be {@code null}.
   *
   * @return  {@code true} if this add request contains an attribute with the
   *          specified name and value, or {@code false} if not.
   */
  boolean hasAttributeValue(@NotNull String attributeName,
                            @NotNull String attributeValue,
                            @NotNull MatchingRule matchingRule);



  /**
   * Indicates whether this add request contains an attribute with the given
   * name and value.
   *
   * @param  attributeName   The name of the attribute for which to make the
   *                         determination.  It must not be {@code null}.
   * @param  attributeValue  The value for which to make the determination.  It
   *                         must not be {@code null}.
   *
   * @return  {@code true} if this add request  contains an attribute with the
   *          specified name and value, or {@code false} if not.
   */
  boolean hasAttributeValue(@NotNull String attributeName,
                            @NotNull byte[] attributeValue);



  /**
   * Indicates whether this add request contains an attribute with the given
   * name and value.
   *
   * @param  attributeName   The name of the attribute for which to make the
   *                         determination.  It must not be {@code null}.
   * @param  attributeValue  The value for which to make the determination.  It
   *                         must not be {@code null}.
   * @param  matchingRule    The matching rule to use to make the determination.
   *                         It must not be {@code null}.
   *
   * @return  {@code true} if this add request  contains an attribute with the
   *          specified name and value, or {@code false} if not.
   */
  boolean hasAttributeValue(@NotNull String attributeName,
                            @NotNull byte[] attributeValue,
                            @NotNull MatchingRule matchingRule);



  /**
   * Indicates whether this add request contains the specified object class.
   *
   * @param  objectClassName  The name of the object class for which to make the
   *                          determination.  It must not be {@code null}.
   *
   * @return  {@code true} if this add request contains the specified object
   *          class, or {@code false} if not.
   */
  boolean hasObjectClass(@NotNull String objectClassName);



  /**
   * Retrieves an {@code Entry} object containing the DN and attributes of this
   * add request.
   *
   * @return  An {@code Entry} object containing the DN and attributes of this
   *          add request.
   */
  @NotNull()
  Entry toEntry();



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  AddRequest duplicate();



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  AddRequest duplicate(@Nullable Control[] controls);



  /**
   * Retrieves an LDIF add change record with the contents of this add request.
   *
   * @return  An LDIF add change record with the contents of this add request.
   */
  @NotNull()
  LDIFAddChangeRecord toLDIFChangeRecord();



  /**
   * Retrieves a string array whose lines contain an LDIF representation of the
   * corresponding add change record.
   *
   * @return  A string array whose lines contain an LDIF representation of the
   *          corresponding add change record.
   */
  @NotNull()
  String[] toLDIF();



  /**
   * Retrieves an LDIF string representation of this add request.
   *
   * @return  An LDIF string representation of this add request.
   */
  @NotNull()
  String toLDIFString();
}
