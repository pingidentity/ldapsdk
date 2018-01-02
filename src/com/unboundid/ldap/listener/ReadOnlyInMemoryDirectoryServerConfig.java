/*
 * Copyright 2011-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2018 Ping Identity Corporation
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
              final InMemoryDirectoryServerConfig config)
  {
    super(config);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
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
  public void setBaseDNs(final String... baseDNs)
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
  public void setBaseDNs(final DN... baseDNs)
         throws LDAPException, UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned list will not be modifiable.
   */
  @Override()
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
                   final InMemoryListenerConfig... listenerConfigs)
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
                   final Collection<InMemoryListenerConfig> listenerConfigs)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned set will not be modifiable.
   */
  @Override()
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
  public void setAllowedOperationTypes(final OperationType... operationTypes)
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
                   final Collection<OperationType> operationTypes)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned set will not be modifiable.
   */
  @Override()
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
                   final OperationType... operationTypes)
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
                   final Collection<OperationType> operationTypes)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned map will not be modifiable.
   */
  @Override()
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
  public void addAdditionalBindCredentials(final String dn,
                                           final String password)
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
  public void addAdditionalBindCredentials(final String dn,
                                           final byte[] password)
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
                   final LDAPListenerExceptionHandler exceptionHandler)
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
  public void setSchema(final Schema schema)
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
  public void setAccessLogHandler(final Handler accessLogHandler)
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
  public void setLDAPDebugLogHandler(final Handler ldapDebugLogHandler)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned list will not be modifiable.
   */
  @Override()
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
                   final InMemoryExtendedOperationHandler handler)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned list will not be modifiable.
   */
  @Override()
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
  public void addSASLBindHandler(final InMemorySASLBindHandler handler)
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
                   final String... equalityIndexAttributes)
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
                   final Collection<String> equalityIndexAttributes)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * {@inheritDoc}  The returned set will not be modifiable.
   */
  @Override()
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
                   final String... referentialIntegrityAttributes)
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
                   final Collection<String> referentialIntegrityAttributes)
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
  public void setVendorName(final String vendorName)
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
  public void setVendorVersion(final String vendorVersion)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }
}
