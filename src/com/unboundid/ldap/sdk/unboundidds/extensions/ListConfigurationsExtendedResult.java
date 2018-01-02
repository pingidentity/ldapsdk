/*
 * Copyright 2013-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended result that can be used
 * to retrieve a list of all available versions of the configuration within a
 * server.  This may include not only the currently-active configuration, but
 * also former configurations that have been archived, and the baseline
 * configuration for the current server version.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The OID for this extended result is 1.3.6.1.4.1.30221.2.6.27.  If the request
 * was processed successfully, then the response will have a value with the
 * following encoding:
 * <PRE>
 *   ListConfigurationsResult ::= SEQUENCE {
 *        activeConfigFileName        [0] OCTET STRING,
 *        baselineConfigFileNames     [1] OCTET STRING OPTIONAL,
 *        archivedConfigFileNames     [2] SEQUENCE OF OCTET STRING OPTIONAL,
 *        ... }
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ListConfigurationsExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.27) for the list configurations extended
   * result.
   */
  public static final String LIST_CONFIGS_RESULT_OID =
       "1.3.6.1.4.1.30221.2.6.27";



  /**
   * The BER type for the element holding the filename used for the active
   * configuration.
   */
  private static final byte TYPE_ACTIVE_CONFIG_FILE_NAME = (byte) 0x80;



  /**
   * The BER type for the element holding the filename used for the baseline
   * configuration.
   */
  private static final byte TYPE_BASELINE_CONFIG_FILE_NAMES = (byte) 0xA1;



  /**
   * The BER type for the element holding the filenames used for the archived
   * configurations.
   */
  private static final byte TYPE_ARCHIVED_CONFIG_FILE_NAMES = (byte) 0xA2;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -466738484294922561L;



  // The names of the archived configuration files.
  private final List<String> archivedFileNames;

  // The name of the baseline configuration file.
  private final List<String> baselineFileNames;

  // The name of the active configuration file.
  private final String activeFileName;



  /**
   * Creates a new list configurations extended result from the provided generic
   * extended result.
   *
   * @param  result  The generic extended result to be decoded as a list
   *                 configurations extended result.
   *
   * @throws LDAPException  If the provided extended result cannot be parsed as
   *                         a valid list configurations extended result.
   */
  public ListConfigurationsExtendedResult(final ExtendedResult result)
       throws LDAPException
  {
    super(result);

    final ASN1OctetString value = result.getValue();
    if (value == null)
    {
      activeFileName = null;
      baselineFileNames = Collections.emptyList();
      archivedFileNames = Collections.emptyList();
      return;
    }

    try
    {
      String activeName = null;
      List<String> archivedNames = Collections.emptyList();
      List<String> baselineNames = null;
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      for (final ASN1Element e : elements)
      {
        switch (e.getType())
        {
          case TYPE_ACTIVE_CONFIG_FILE_NAME:
            activeName = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_BASELINE_CONFIG_FILE_NAMES:
            final ASN1Element[] baselineNameElements =
                 ASN1Sequence.decodeAsSequence(e).elements();
            baselineNames = new ArrayList<String>(baselineNameElements.length);
            for (final ASN1Element el : baselineNameElements)
            {
              baselineNames.add(
                   ASN1OctetString.decodeAsOctetString(el).stringValue());
            }
            archivedNames = Collections.unmodifiableList(baselineNames);
            break;
          case TYPE_ARCHIVED_CONFIG_FILE_NAMES:
            final ASN1Element[] archivedNameElements =
                 ASN1Sequence.decodeAsSequence(e).elements();
            archivedNames = new ArrayList<String>(archivedNameElements.length);
            for (final ASN1Element el : archivedNameElements)
            {
              archivedNames.add(
                   ASN1OctetString.decodeAsOctetString(el).stringValue());
            }
            archivedNames = Collections.unmodifiableList(archivedNames);
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_LIST_CONFIGS_RESULT_UNEXPECTED_ELEMENT_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }

      activeFileName    = activeName;
      archivedFileNames = archivedNames;
      baselineFileNames = baselineNames;

      if (activeFileName == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LIST_CONFIGS_RESULT_NO_ACTIVE_CONFIG.get());
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LIST_CONFIGS_RESULT_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a new list configurations extended result with the provided
   * information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  activeFileName     The name of the active configuration file, if
   *                            available.
   * @param  baselineFileNames  The names of the baseline configuration files
   *                            for current and former server versions, if
   *                            available.  It must be {@code null} or empty if
   *                            the active file name is {@code null}.
   * @param  archivedFileNames  The names of the archived configuration files,
   *                            if available.  It must be {@code null} or empty
   *                            if the active file name is {@code null}.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public ListConfigurationsExtendedResult(final int messageID,
              final ResultCode resultCode, final String diagnosticMessage,
              final String matchedDN, final String[] referralURLs,
              final String activeFileName,
              final Collection<String> baselineFileNames,
              final Collection<String> archivedFileNames,
              final Control... responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         ((activeFileName == null) ? null : LIST_CONFIGS_RESULT_OID),
         encodeValue(activeFileName, baselineFileNames, archivedFileNames),
         responseControls);

    this.activeFileName   = activeFileName;

    if (baselineFileNames == null)
    {
      this.baselineFileNames = Collections.emptyList();
    }
    else
    {
      this.baselineFileNames = Collections.unmodifiableList(
           new ArrayList<String>(baselineFileNames));
    }

    if (archivedFileNames == null)
    {
      this.archivedFileNames = Collections.emptyList();
    }
    else
    {
      this.archivedFileNames = Collections.unmodifiableList(
           new ArrayList<String>(archivedFileNames));
    }
  }



  /**
   * Creates an ASN.1 octet string containing an encoded representation of the
   * value for a list configurations extended result with the provided
   * information.
   *
   * @param  activeFileName     The name of the active configuration file, if
   *                            available.
   * @param  baselineFileNames  The names of the baseline configuration files
   *                            for current and former server versions, if
   *                            available.  It must be {@code null} or empty if
   *                            the active file name is {@code null}.
   * @param  archivedFileNames  The names of the archived configuration files,
   *                            if available.  It must be {@code null} or empty
   *                            if the active file name is {@code null}.
   *
   * @return  An ASN.1 octet string containing an encoded representation of the
   *          value for a list configurations extended result, or {@code null}
   *          if a result with the provided information should not have a value.
   */
  public static ASN1OctetString encodeValue(final String activeFileName,
                     final Collection<String> baselineFileNames,
                     final Collection<String> archivedFileNames)
  {
    if (activeFileName == null)
    {
      Validator.ensureTrue(
           ((baselineFileNames == null) || baselineFileNames.isEmpty()),
           "The baseline filename must be null if the active filename is null");
      Validator.ensureTrue(
           ((archivedFileNames == null) || archivedFileNames.isEmpty()),
           "The archived filenames must be null or empty if the active " +
                "filename is null");
      return null;
    }

    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(3);
    elements.add(
         new ASN1OctetString(TYPE_ACTIVE_CONFIG_FILE_NAME, activeFileName));

    if ((baselineFileNames != null) && (! baselineFileNames.isEmpty()))
    {
      final TreeSet<String> sortedBaselineNames =
           new TreeSet<String>(baselineFileNames);
      final ArrayList<ASN1Element> baselineNameElements =
           new ArrayList<ASN1Element>(sortedBaselineNames.size());
      for (final String s : sortedBaselineNames)
      {
        baselineNameElements.add(new ASN1OctetString(s));
      }
      elements.add(new ASN1Sequence(TYPE_BASELINE_CONFIG_FILE_NAMES,
           baselineNameElements));
    }

    if ((archivedFileNames != null) && (! archivedFileNames.isEmpty()))
    {
      final TreeSet<String> sortedArchivedNames =
           new TreeSet<String>(archivedFileNames);
      final ArrayList<ASN1Element> archivedNameElements =
           new ArrayList<ASN1Element>(sortedArchivedNames.size());
      for (final String s : sortedArchivedNames)
      {
        archivedNameElements.add(new ASN1OctetString(s));
      }
      elements.add(new ASN1Sequence(TYPE_ARCHIVED_CONFIG_FILE_NAMES,
           archivedNameElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the name of the active configuration file the server is
   * currently using, if available.
   *
   * @return  The name of the active configuration file the server is
   *          currently using, or {@code null} this is not available.
   */
  public String getActiveFileName()
  {
    return activeFileName;
  }



  /**
   * Retrieves a list containing the names of the baseline configuration files
   * (i.e., the files containing the initial "out-of-the-box" configuration for
   * various server versions), if available.
   *
   * @return  A list containing the names of the baseline configuration files,
   *          or an empty list if this is not available.
   */
  public List<String> getBaselineFileNames()
  {
    return baselineFileNames;
  }



  /**
   * Retrieves a list containing the names of the archived configuration files,
   * if available.
   *
   * @return  A list containing the names of the archived configuration files,
   *          or an empty list if this is not available.
   */
  public List<String> getArchivedFileNames()
  {
    return archivedFileNames;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_LIST_CONFIGS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ListConfigurationsExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (activeFileName != null)
    {
      buffer.append(", activeFileName='");
      buffer.append(activeFileName);
      buffer.append('\'');
    }

    if (! baselineFileNames.isEmpty())
    {
      buffer.append(", baselineFileNames={");

      final Iterator<String> iterator = baselineFileNames.iterator();
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

    if (! archivedFileNames.isEmpty())
    {
      buffer.append(", archivedFileNames={");

      final Iterator<String> iterator = archivedFileNames.iterator();
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

    final String diagnosticMessage = getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    final String matchedDN = getMatchedDN();
    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    final String[] referralURLs = getReferralURLs();
    if (referralURLs.length > 0)
    {
      buffer.append(", referralURLs={");
      for (int i=0; i < referralURLs.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append('\'');
        buffer.append(referralURLs[i]);
        buffer.append('\'');
      }
      buffer.append('}');
    }

    final Control[] responseControls = getResponseControls();
    if (responseControls.length > 0)
    {
      buffer.append(", responseControls={");
      for (int i=0; i < responseControls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(responseControls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
