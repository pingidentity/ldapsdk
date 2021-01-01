/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Handler;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a read-only representation of an
 * {@link InMemoryDirectoryServerConfig} object.  All methods for reading the
 * configuration will work the same as they do in the superclass, but any
 * methods which attempt to alter the configuration will throw an
 * {@code UnsupportedOperationException}.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ReadOnlyInMemoryDirectoryServerConfig
       extends InMemoryDirectoryServerConfig
{
  /**
   * Creates a new read-only representation of an in-memory directory server
   * config object using the provided configuration.
   *
   * @param  config  The configuration to use for this read-only representation.
   */
  public ReadOnlyInMemoryDirectoryServerConfig(
              @NotNull final InMemoryDirectoryServerConfig config)
  {
    super(config);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public DN[] getBaseDNs()
  {
    final DN[] origBaseDNs = super.getBaseDNs();

    final DN[] baseDNsCopy = new DN[origBaseDNs.length];
    System.arraycopy(origBaseDNs, 0, baseDNsCopy, 0, baseDNsCopy.length);

    return baseDNsCopy;
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setBaseDNs(@NotNull final String... baseDNs)
         throws LDAPException, UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setBaseDNs(@NotNull final DN... baseDNs)
         throws LDAPException, UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned list will not be modifiable.
   */
  @Override()
  @NotNull()
  public List<InMemoryListenerConfig> getListenerConfigs()
  {
    return Collections.unmodifiableList(super.getListenerConfigs());
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setListenerConfigs(
                   @NotNull final InMemoryListenerConfig... listenerConfigs)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setListenerConfigs(
              @NotNull final Collection<InMemoryListenerConfig> listenerConfigs)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned set will not be modifiable.
   */
  @Override()
  @NotNull()
  public Set<OperationType> getAllowedOperationTypes()
  {
    return Collections.unmodifiableSet(super.getAllowedOperationTypes());
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setAllowedOperationTypes(
                   @Nullable final OperationType... operationTypes)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setAllowedOperationTypes(
                   @Nullable final Collection<OperationType> operationTypes)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned set will not be modifiable.
   */
  @Override()
  @NotNull()
  public Set<OperationType> getAuthenticationRequiredOperationTypes()
  {
    return Collections.unmodifiableSet(
         super.getAuthenticationRequiredOperationTypes());
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setAuthenticationRequiredOperationTypes(
                   @Nullable final OperationType... operationTypes)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setAuthenticationRequiredOperationTypes(
                   @Nullable final Collection<OperationType> operationTypes)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned map will not be modifiable.
   */
  @Override()
  @NotNull()
  public Map<DN,byte[]> getAdditionalBindCredentials()
  {
    return Collections.unmodifiableMap(super.getAdditionalBindCredentials());
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void addAdditionalBindCredentials(@NotNull final String dn,
                                           @NotNull final String password)
         throws LDAPException, UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void addAdditionalBindCredentials(@NotNull final String dn,
                                           @NotNull final byte[] password)
         throws LDAPException, UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setListenerExceptionHandler(
                   @NotNull final LDAPListenerExceptionHandler exceptionHandler)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setSchema(@Nullable final Schema schema)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   */
  @Override()
  public void setEnforceAttributeSyntaxCompliance(
                   final boolean enforceAttributeSyntaxCompliance)
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   */
  @Override()
  public void setEnforceSingleStructuralObjectClass(
                   final boolean enforceSingleStructuralObjectClass)
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setAccessLogHandler(@Nullable final Handler accessLogHandler)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setLDAPDebugLogHandler(
                   @Nullable final Handler ldapDebugLogHandler)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned list will not be modifiable.
   */
  @Override()
  @NotNull()
  public List<InMemoryExtendedOperationHandler> getExtendedOperationHandlers()
  {
    return Collections.unmodifiableList(super.getExtendedOperationHandlers());
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void addExtendedOperationHandler(
                   @NotNull final InMemoryExtendedOperationHandler handler)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned list will not be modifiable.
   */
  @Override()
  @NotNull()
  public List<InMemorySASLBindHandler> getSASLBindHandlers()
  {
    return Collections.unmodifiableList(super.getSASLBindHandlers());
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void addSASLBindHandler(@NotNull final InMemorySASLBindHandler handler)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setGenerateOperationalAttributes(
                   final boolean generateOperationalAttributes)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setMaxChangeLogEntries(final int maxChangeLogEntries)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned list will not be modifiable.
   */
  @Override()
  @NotNull()
  public List<String> getEqualityIndexAttributes()
  {
    return Collections.unmodifiableList(super.getEqualityIndexAttributes());
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setEqualityIndexAttributes(
                   @Nullable final String... equalityIndexAttributes)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setEqualityIndexAttributes(
                   @Nullable final Collection<String> equalityIndexAttributes)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned set will not be modifiable.
   */
  @Override()
  @NotNull()
  public Set<String> getReferentialIntegrityAttributes()
  {
    return Collections.unmodifiableSet(
         super.getReferentialIntegrityAttributes());
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setReferentialIntegrityAttributes(
                   @Nullable final String... referentialIntegrityAttributes)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setReferentialIntegrityAttributes(
              @Nullable final Collection<String> referentialIntegrityAttributes)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setVendorName(@Nullable final String vendorName)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  This method will always throw an
   * {@code UnsupportedOperationException}.
   *
   * @throws  UnsupportedOperationException  To indicate that this object cannot
   *                                         be altered.
   */
  @Override()
  public void setVendorVersion(@Nullable final String vendorVersion)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }
}
