/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



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
  private volatile DN parsedNewSuperiorDN;

  // The parsed new RDN for the entry.
  private volatile RDN parsedNewRDN;

  // The new RDN value for the entry.
  private final String newRDN;

  // The new superior DN for the entry, if available.
  private final String newSuperiorDN;



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
  public LDIFModifyDNChangeRecord(final String dn, final String newRDN,
                                  final boolean deleteOldRDN,
                                  final String newSuperiorDN)
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
  public LDIFModifyDNChangeRecord(final String dn, final String newRDN,
                                  final boolean deleteOldRDN,
                                  final String newSuperiorDN,
                                  final List<Control> controls)
  {
    super(dn, controls);

    ensureNotNull(newRDN);

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
  public LDIFModifyDNChangeRecord(final ModifyDNRequest modifyDNRequest)
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
  public ChangeType getChangeType()
  {
    return ChangeType.MODIFY_DN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPResult processChange(final LDAPInterface connection,
                                  final boolean includeControls)
         throws LDAPException
  {
    return connection.modifyDN(toModifyDNRequest(includeControls));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String[] toLDIF(final int wrapColumn)
  {
    List<String> ldifLines = new ArrayList<String>(10);
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
  public void toLDIF(final ByteStringBuffer buffer, final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
         wrapColumn);
    buffer.append(EOL_BYTES);

    for (final Control c : getControls())
    {
      LDIFWriter.encodeNameAndValue("control", encodeControlString(c), buffer,
           wrapColumn);
      buffer.append(EOL_BYTES);
    }

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("moddn"),
                                  buffer, wrapColumn);
    buffer.append(EOL_BYTES);

    LDIFWriter.encodeNameAndValue("newrdn", new ASN1OctetString(newRDN), buffer,
                                  wrapColumn);
    buffer.append(EOL_BYTES);

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
    buffer.append(EOL_BYTES);

    if (newSuperiorDN != null)
    {
      LDIFWriter.encodeNameAndValue("newsuperior",
                                    new ASN1OctetString(newSuperiorDN), buffer,
                                    wrapColumn);
      buffer.append(EOL_BYTES);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toLDIFString(final StringBuilder buffer, final int wrapColumn)
  {
    LDIFWriter.encodeNameAndValue("dn", new ASN1OctetString(getDN()), buffer,
                                  wrapColumn);
    buffer.append(EOL);

    for (final Control c : getControls())
    {
      LDIFWriter.encodeNameAndValue("control", encodeControlString(c), buffer,
           wrapColumn);
      buffer.append(EOL);
    }

    LDIFWriter.encodeNameAndValue("changetype", new ASN1OctetString("moddn"),
                                  buffer, wrapColumn);
    buffer.append(EOL);

    LDIFWriter.encodeNameAndValue("newrdn", new ASN1OctetString(newRDN), buffer,
                                  wrapColumn);
    buffer.append(EOL);

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
    buffer.append(EOL);

    if (newSuperiorDN != null)
    {
      LDIFWriter.encodeNameAndValue("newsuperior",
                                    new ASN1OctetString(newSuperiorDN), buffer,
                                    wrapColumn);
      buffer.append(EOL);
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
      debugException(e);
      hashCode = toLowerCase(getDN()).hashCode() +
                 toLowerCase(newRDN).hashCode();
      if (newSuperiorDN != null)
      {
        hashCode += toLowerCase(newSuperiorDN).hashCode();
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
  public boolean equals(final Object o)
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

    final HashSet<Control> c1 = new HashSet<Control>(getControls());
    final HashSet<Control> c2 = new HashSet<Control>(r.getControls());
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
      debugException(e);
      if (! toLowerCase(getDN()).equals(toLowerCase(r.getDN())))
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
      debugException(e);
      if (! toLowerCase(newRDN).equals(toLowerCase(r.newRDN)))
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
        debugException(e);
        if (! toLowerCase(newSuperiorDN).equals(toLowerCase(r.newSuperiorDN)))
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
  public void toString(final StringBuilder buffer)
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
