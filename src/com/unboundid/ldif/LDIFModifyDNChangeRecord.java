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
package com.unboundid.ldif;



import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class defines an LDIF modify DN change record, which can be used to
 * represent an LDAP modify DN request.  See the documentation for the
 * {@link LDIFChangeRecord} class for an example demonstrating the process for
 * interacting with LDIF change records.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDIFModifyDNChangeRecord
       extends LDIFChangeRecord
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5804442145450388071L;



  // Indicates whether to delete the current RDN value.
  private final boolean deleteOldRDN;

  // The parsed new superior DN for the entry.
  @Nullable private volatile DN parsedNewSuperiorDN;

  // The parsed new RDN for the entry.
  @Nullable private volatile RDN parsedNewRDN;

  // The new RDN value for the entry.
  @NotNull private final String newRDN;

  // The new superior DN for the entry, if available.
  @Nullable private final String newSuperiorDN;



  /**
   * Creates a new LDIF modify DN change record with the provided information.
   *
   * @param  dn             The current DN for the entry.  It must not be
   *                        {@code null}.
   * @param  newRDN         The new RDN value for the entry.  It must not be
   *                        {@code null}.
   * @param  deleteOldRDN   Indicates whether to delete the currentRDN value
   *                        from the entry.
   * @param  newSuperiorDN  The new superior DN for this LDIF modify DN change
   *                        record.  It may be {@code null} if the entry is not
   *                        to be moved below a new parent.
   */
  public LDIFModifyDNChangeRecord(@NotNull final String dn,
                                  @NotNull final String newRDN,
                                  final boolean deleteOldRDN,
                                  @Nullable final String newSuperiorDN)
  {
    this(dn, newRDN, deleteOldRDN, newSuperiorDN, null);
  }



  /**
   * Creates a new LDIF modify DN change record with the provided information.
   *
   * @param  dn             The current DN for the entry.  It must not be
   *                        {@code null}.
   * @param  newRDN         The new RDN value for the entry.  It must not be
   *                        {@code null}.
   * @param  deleteOldRDN   Indicates whether to delete the currentRDN value
   *                        from the entry.
   * @param  newSuperiorDN  The new superior DN for this LDIF modify DN change
   *                        record.  It may be {@code null} if the entry is not
   *                        to be moved below a new parent.
   * @param  controls       The set of controls for this LDIF modify DN change
   *                        record.  It may be {@code null} or empty if there
   *                        are no controls.
   */
  public LDIFModifyDNChangeRecord(@NotNull final String dn,
                                  @NotNull final String newRDN,
                                  final boolean deleteOldRDN,
                                  @Nullable final String newSuperiorDN,
                                  @Nullable final List<Control> controls)
  {
    super(dn, controls);

    Validator.ensureNotNull(newRDN);

    this.newRDN        = newRDN;
    this.deleteOldRDN  = deleteOldRDN;
    this.newSuperiorDN = newSuperiorDN;

    parsedNewRDN        = null;
    parsedNewSuperiorDN = null;
  }



  /**
   * Creates a new LDIF modify DN change record from the provided modify DN
   * request.
   *
   * @param  modifyDNRequest  The modify DN request to use to create this LDIF
   *                          modify DN change record.  It must not be
   *                          {@code null}.
   */
  public LDIFModifyDNChangeRecord(
              @NotNull final ModifyDNRequest modifyDNRequest)
  {
    super(modifyDNRequest.getDN(), modifyDNRequest.getControlList());

    newRDN        = modifyDNRequest.getNewRDN();
    deleteOldRDN  = modifyDNRequest.deleteOldRDN();
    newSuperiorDN = modifyDNRequest.getNewSuperiorDN();

    parsedNewRDN        = null;
    parsedNewSuperiorDN = null;
  }



  /**
   * Retrieves the new RDN value for the entry.
   *
   * @return  The new RDN value for the entry.
   */
  @NotNull()
  public String getNewRDN()
  {
    return newRDN;
  }



  /**
   * Retrieves the parsed new RDN value for the entry.
   *
   * @return  The parsed new RDN value for the entry.
   *
   * @throws  LDAPException  If a problem occurs while trying to parse the new
   *                         RDN.
   */
  @NotNull()
  public RDN getParsedNewRDN()
         throws LDAPException
  {
    if (parsedNewRDN == null)
    {
      parsedNewRDN = new RDN(newRDN);
    }

    return parsedNewRDN;
  }



  /**
   * Indicates whether to delete the current RDN value from the entry.
   *
   * @return  {@code true} if the current RDN value should be removed from the
   *          entry, or {@code false} if not.
   */
  public boolean deleteOldRDN()
  {
    return deleteOldRDN;
  }



  /**
   * Retrieves the new superior DN for the entry, if applicable.
   *
   * @return  The new superior DN for the entry, or {@code null} if the entry is
   *          not to be moved below a new parent.
   */
  @Nullable()
  public String getNewSuperiorDN()
  {
    return newSuperiorDN;
  }



  /**
   * Retrieves the parsed new superior DN for the entry, if applicable.
   *
   * @return  The parsed new superior DN for the entry, or {@code null} if the
   *          entry is not to be moved below a new parent.
   *
   * @throws  LDAPException  If a problem occurs while trying to parse the new
   *                         superior DN.
   */
  @Nullable()
  public DN getParsedNewSuperiorDN()
         throws LDAPException
  {
    if ((parsedNewSuperiorDN == null) && (newSuperiorDN != null))
    {
      parsedNewSuperiorDN = new DN(newSuperiorDN);
    }

    return parsedNewSuperiorDN;
  }



  /**
   * Retrieves the DN that the entry should have after the successful completion
   * of the operation.
   *
   * @return  The DN that the entry should have after the successful completion
   *          of the operation.
   *
   * @throws  LDAPException  If a problem occurs while trying to parse the
   *                         target DN, new RDN, or new superior DN.
   */
  @NotNull()
  public DN getNewDN()
         throws LDAPException
  {
    if (newSuperiorDN == null)
    {
      final DN parentDN = getParsedDN().getParent();
      if (parentDN == null)
      {
        return new DN(getParsedNewRDN());
      }
      else
      {
        return new DN(getParsedNewRDN(), parentDN);
      }
    }
    else
    {
      return new DN(getParsedNewRDN(), getParsedNewSuperiorDN());
    }
  }



  /**
   * Creates a modify DN request from this LDIF modify DN change record.  Any
   * change record controls will be included in the request
   *
   * @return  The modify DN request created from this LDIF modify DN change
   *          record.
   */
  @NotNull()
  public ModifyDNRequest toModifyDNRequest()
  {
    return toModifyDNRequest(true);
  }



  /**
   * Creates a modify DN request from this LDIF modify DN change record,
   * optionally including any change record controls in the request.
   *
   * @param  includeControls  Indicates whether to include any controls in the
   *                          request.
   *
   * @return  The modify DN request created from this LDIF modify DN change
   *          record.
   */
  @NotNull()
  public ModifyDNRequest toModifyDNRequest(final boolean includeControls)
  {
    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest(getDN(), newRDN, deleteOldRDN, newSuperiorDN);
    if (includeControls)
    {
      modifyDNRequest.setControls(getControls());
    }

    return modifyDNRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ChangeType getChangeType()
  {
    return ChangeType.MODIFY_DN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDIFModifyDNChangeRecord duplicate(@Nullable final Control... controls)
  {
    return new LDIFModifyDNChangeRecord(getDN(), newRDN, deleteOldRDN,
         newSuperiorDN, StaticUtils.toList(controls));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPResult processChange(@NotNull final LDAPInterface connection,
                                  final boolean includeControls)
         throws LDAPException
  {
    return connection.modifyDN(toModifyDNRequest(includeControls));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String[] toLDIF(final int wrapColumn)
  {
    List<String> ldifLines = new ArrayList<>(10);
    encodeNameAndValue("dn", new ASN1OctetString(getDN()), ldifLines);

    for (final Control c : getControls())
    {
      encodeNameAndValue("control", encodeControlString(c), ldifLines);
    }

    ldifLines.add("changetype: moddn");
    encodeNameAndValue("newrdn", new ASN1OctetString(newRDN), ldifLines);
    ldifLines.add("deleteoldrdn: " + (deleteOldRDN ? "1" : "0"));

    if (newSuperiorDN != null)
    {
      encodeNameAndValue("newsuperior", new ASN1OctetString(newSuperiorDN),
           ldifLines);
    }

    if (wrapColumn > 2)
    {
      ldifLines = LDIFWriter.wrapLines(wrapColumn, ldifLines);
    }

    final String[] ldifArray = new String[ldifLines.size()];
    ldifLines.toArray(ldifArray);
    return ldifArray;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toLDIF(@NotNull final ByteStringBuffer buffer,
                     final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
         wrapColumn);
    buffer.append(StaticUtils.EOL_BYTES);

    for (final Control c : getControls())
    {
      LDIFWriter.encodeNameAndValue("control", encodeControlString(c), buffer,
           wrapColumn);
      buffer.append(StaticUtils.EOL_BYTES);
    }

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("moddn"),
                                  buffer, wrapColumn);
    buffer.append(StaticUtils.EOL_BYTES);

    LDIFWriter.encodeNameAndValue("newrdn", new ASN1OctetString(newRDN), buffer,
                                  wrapColumn);
    buffer.append(StaticUtils.EOL_BYTES);

    if (deleteOldRDN)
    {
      LDIFWriter.encodeNameAndValue("deleteoldrdn", new ASN1OctetString("1"),
                                    buffer, wrapColumn);
    }
    else
    {
      LDIFWriter.encodeNameAndValue("deleteoldrdn", new ASN1OctetString("0"),
                                    buffer, wrapColumn);
    }
    buffer.append(StaticUtils.EOL_BYTES);

    if (newSuperiorDN != null)
    {
      LDIFWriter.encodeNameAndValue("newsuperior",
                                    new ASN1OctetString(newSuperiorDN), buffer,
                                    wrapColumn);
      buffer.append(StaticUtils.EOL_BYTES);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toLDIFString(@NotNull final StringBuilder buffer,
                           final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
                                  wrapColumn);
    buffer.append(StaticUtils.EOL);

    for (final Control c : getControls())
    {
      LDIFWriter.encodeNameAndValue("control", encodeControlString(c), buffer,
           wrapColumn);
      buffer.append(StaticUtils.EOL);
    }

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("moddn"),
                                  buffer, wrapColumn);
    buffer.append(StaticUtils.EOL);

    LDIFWriter.encodeNameAndValue("newrdn", new ASN1OctetString(newRDN), buffer,
                                  wrapColumn);
    buffer.append(StaticUtils.EOL);

    if (deleteOldRDN)
    {
      LDIFWriter.encodeNameAndValue("deleteoldrdn", new ASN1OctetString("1"),
                                    buffer, wrapColumn);
    }
    else
    {
      LDIFWriter.encodeNameAndValue("deleteoldrdn", new ASN1OctetString("0"),
                                    buffer, wrapColumn);
    }
    buffer.append(StaticUtils.EOL);

    if (newSuperiorDN != null)
    {
      LDIFWriter.encodeNameAndValue("newsuperior",
                                    new ASN1OctetString(newSuperiorDN), buffer,
                                    wrapColumn);
      buffer.append(StaticUtils.EOL);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int hashCode()
  {
    int hashCode;
    try
    {
      hashCode = getParsedDN().hashCode() + getParsedNewRDN().hashCode();
      if (newSuperiorDN != null)
      {
        hashCode += getParsedNewSuperiorDN().hashCode();
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      hashCode = StaticUtils.toLowerCase(getDN()).hashCode() +
                 StaticUtils.toLowerCase(newRDN).hashCode();
      if (newSuperiorDN != null)
      {
        hashCode += StaticUtils.toLowerCase(newSuperiorDN).hashCode();
      }
    }

    if (deleteOldRDN)
    {
      hashCode++;
    }

    return hashCode;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof LDIFModifyDNChangeRecord))
    {
      return false;
    }

    final LDIFModifyDNChangeRecord r = (LDIFModifyDNChangeRecord) o;

    final HashSet<Control> c1 = new HashSet<>(getControls());
    final HashSet<Control> c2 = new HashSet<>(r.getControls());
    if (! c1.equals(c2))
    {
      return false;
    }

    try
    {
      if (! getParsedDN().equals(r.getParsedDN()))
      {
        return false;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      if (! StaticUtils.toLowerCase(getDN()).equals(
           StaticUtils.toLowerCase(r.getDN())))
      {
        return false;
      }
    }

    try
    {
      if (! getParsedNewRDN().equals(r.getParsedNewRDN()))
      {
        return false;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      if (! StaticUtils.toLowerCase(newRDN).equals(
           StaticUtils.toLowerCase(r.newRDN)))
      {
        return false;
      }
    }

    if (newSuperiorDN == null)
    {
      if (r.newSuperiorDN != null)
      {
        return false;
      }
    }
    else
    {
      if (r.newSuperiorDN == null)
      {
        return false;
      }

      try
      {
        if (! getParsedNewSuperiorDN().equals(r.getParsedNewSuperiorDN()))
        {
          return false;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        if (! StaticUtils.toLowerCase(newSuperiorDN).equals(
             StaticUtils.toLowerCase(r.newSuperiorDN)))
        {
          return false;
        }
      }
    }

    return (deleteOldRDN == r.deleteOldRDN);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDIFModifyDNChangeRecord(dn='");
    buffer.append(getDN());
    buffer.append("', newRDN='");
    buffer.append(newRDN);
    buffer.append("', deleteOldRDN=");
    buffer.append(deleteOldRDN);

    if (newSuperiorDN != null)
    {
      buffer.append(", newSuperiorDN='");
      buffer.append(newSuperiorDN);
      buffer.append('\'');
    }

    final List<Control> controls = getControls();
    if (! controls.isEmpty())
    {
      buffer.append(", controls={");

      final Iterator<Control> iterator = controls.iterator();
      while (iterator.hasNext())
      {
        iterator.next().toString(buffer);
        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
    }

    buffer.append(')');
  }
}
