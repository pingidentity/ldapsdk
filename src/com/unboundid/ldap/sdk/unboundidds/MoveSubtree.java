/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.io.OutputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.UnsolicitedNotificationHandler;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.controls.DraftLDUPSubentriesRequestControl;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OperationPurposeRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            RealAttributesOnlyRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            ReturnConflictEntriesRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            SoftDeletedEntryAccessRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            SuppressReferentialIntegrityUpdatesRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            GetSubtreeAccessibilityExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            GetSubtreeAccessibilityExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            SetSubtreeAccessibilityExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            SubtreeAccessibilityRestriction;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            SubtreeAccessibilityState;
import com.unboundid.util.Debug;
import com.unboundid.util.MultiServerLDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ReverseComparator;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides a utility that may be used to move a single entry or a
 * small subtree of entries from one server to another.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class MoveSubtree
       extends MultiServerLDAPCommandLineTool
       implements UnsolicitedNotificationHandler, MoveSubtreeListener
{
  /**
   * The name of the attribute that appears in the root DSE of Ping
   * Identity, UnboundID, and Nokia/Alcatel-Lucent 8661 Directory Server
   * instances to provide a unique identifier that will be generated every time
   * the server starts.
   */
  @NotNull private static final String ATTR_STARTUP_UUID = "startupUUID";



  // The argument used to indicate whether to operate in verbose mode.
  @Nullable private BooleanArgument verbose = null;

  // The argument used to specify the base DNs of the subtrees to move.
  @Nullable private DNArgument baseDN = null;

  // The argument used to specify a file with base DNs of the subtrees to move.
  @Nullable private FileArgument baseDNFile = null;

  // The argument used to specify the maximum number of entries to move.
  @Nullable private IntegerArgument sizeLimit = null;

  // A message that will be displayed if the tool is interrupted.
  @Nullable private volatile String interruptMessage = null;

  // The argument used to specify the purpose for the move.
  @Nullable private StringArgument purpose = null;



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode rc = main(args, System.out, System.err);
    if (rc != ResultCode.SUCCESS)
    {
      System.exit(Math.max(rc.intValue(), 255));
    }
  }



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
   *
   * @param  args  The command line arguments provided to this program.
   * @param  out   The output stream to which standard out should be written.
   *               It may be {@code null} if output should be suppressed.
   * @param  err   The output stream to which standard error should be written.
   *               It may be {@code null} if error messages should be
   *               suppressed.
   *
   * @return  A result code indicating whether the processing was successful.
   */
  @NotNull()
  public static ResultCode main(@NotNull final String[] args,
                                @Nullable final OutputStream out,
                                @Nullable final OutputStream err)
  {
    final MoveSubtree moveSubtree = new MoveSubtree(out, err);
    return moveSubtree.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided output and error
   * streams.
   *
   * @param  out  The output stream to which standard out should be written.  It
   *              may be {@code null} if output should be suppressed.
   * @param  err  The output stream to which standard error should be written.
   *              It may be {@code null} if error messages should be suppressed.
   */
  public MoveSubtree(@Nullable final OutputStream out,
                     @Nullable final OutputStream err)
  {
    super(out, err, new String[] { "source", "target" }, null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "move-subtree";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_MOVE_SUBTREE_TOOL_DESCRIPTION.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    baseDN = new DNArgument('b', "baseDN", false, 0,
         INFO_MOVE_SUBTREE_ARG_BASE_DN_PLACEHOLDER.get(),
         INFO_MOVE_SUBTREE_ARG_BASE_DN_DESCRIPTION.get());
    baseDN.addLongIdentifier("entryDN", true);
    parser.addArgument(baseDN);

    baseDNFile = new FileArgument('f', "baseDNFile", false, 1,
         INFO_MOVE_SUBTREE_ARG_BASE_DN_FILE_PLACEHOLDER.get(),
         INFO_MOVE_SUBTREE_ARG_BASE_DN_FILE_DESCRIPTION.get(), true, true,
         true, false);
    baseDNFile.addLongIdentifier("entryDNFile", true);
    parser.addArgument(baseDNFile);

    sizeLimit = new IntegerArgument('z', "sizeLimit", false, 1,
         INFO_MOVE_SUBTREE_ARG_SIZE_LIMIT_PLACEHOLDER.get(),
         INFO_MOVE_SUBTREE_ARG_SIZE_LIMIT_DESCRIPTION.get(), 0,
         Integer.MAX_VALUE, 0);
    parser.addArgument(sizeLimit);

    purpose = new StringArgument(null, "purpose", false, 1,
         INFO_MOVE_SUBTREE_ARG_PURPOSE_PLACEHOLDER.get(),
         INFO_MOVE_SUBTREE_ARG_PURPOSE_DESCRIPTION.get());
    parser.addArgument(purpose);

    verbose = new BooleanArgument('v', "verbose", 1,
         INFO_MOVE_SUBTREE_ARG_VERBOSE_DESCRIPTION.get());
    parser.addArgument(verbose);

    parser.addRequiredArgumentSet(baseDN, baseDNFile);
    parser.addExclusiveArgumentSet(baseDN, baseDNFile);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnectionOptions getConnectionOptions()
  {
    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUnsolicitedNotificationHandler(this);
    return options;
  }



  /**
   * Indicates whether this tool should provide arguments for redirecting output
   * to a file.  If this method returns {@code true}, then the tool will offer
   * an "--outputFile" argument that will specify the path to a file to which
   * all standard output and standard error content will be written, and it will
   * also offer a "--teeToStandardOut" argument that can only be used if the
   * "--outputFile" argument is present and will cause all output to be written
   * to both the specified output file and to standard output.
   *
   * @return  {@code true} if this tool should provide arguments for redirecting
   *          output to a file, or {@code false} if not.
   */
  @Override()
  protected boolean supportsOutputFile()
  {
    return true;
  }



  /**
   * Indicates whether this tool supports the use of a properties file for
   * specifying default values for arguments that aren't specified on the
   * command line.
   *
   * @return  {@code true} if this tool supports the use of a properties file
   *          for specifying default values for arguments that aren't specified
   *          on the command line, or {@code false} if not.
   */
  @Override()
  public boolean supportsPropertiesFile()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean logToolInvocationByDefault()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    final List<String> baseDNs;
    if (baseDN.isPresent())
    {
      final List<DN> dnList = baseDN.getValues();
      baseDNs = new ArrayList<>(dnList.size());
      for (final DN dn : dnList)
      {
        baseDNs.add(dn.toString());
      }
    }
    else
    {
      try
      {
        baseDNs = baseDNFile.getNonBlankFileLines();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        err(ERR_MOVE_SUBTREE_ERROR_READING_BASE_DN_FILE.get(
             baseDNFile.getValue().getAbsolutePath(),
             StaticUtils.getExceptionMessage(e)));
        return ResultCode.LOCAL_ERROR;
      }

      if (baseDNs.isEmpty())
      {
        err(ERR_MOVE_SUBTREE_BASE_DN_FILE_EMPTY.get(
             baseDNFile.getValue().getAbsolutePath()));
        return ResultCode.PARAM_ERROR;
      }
    }


    LDAPConnection sourceConnection = null;
    LDAPConnection targetConnection = null;

    try
    {
      try
      {
        sourceConnection = getConnection(0);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err(ERR_MOVE_SUBTREE_CANNOT_CONNECT_TO_SOURCE.get(
             StaticUtils.getExceptionMessage(le)));
        return le.getResultCode();
      }

      try
      {
        targetConnection = getConnection(1);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err(ERR_MOVE_SUBTREE_CANNOT_CONNECT_TO_TARGET.get(
             StaticUtils.getExceptionMessage(le)));
        return le.getResultCode();
      }

      sourceConnection.setConnectionName(
           INFO_MOVE_SUBTREE_CONNECTION_NAME_SOURCE.get());
      targetConnection.setConnectionName(
           INFO_MOVE_SUBTREE_CONNECTION_NAME_TARGET.get());


      // We don't want to accidentally run with the same source and target
      // servers, so perform a couple of checks to verify that isn't the case.
      // First, perform a cheap check to rule out using the same address and
      // port for both source and target servers.
      if (sourceConnection.getConnectedAddress().equals(
               targetConnection.getConnectedAddress()) &&
          (sourceConnection.getConnectedPort() ==
               targetConnection.getConnectedPort()))
      {
        err(ERR_MOVE_SUBTREE_SAME_SOURCE_AND_TARGET_SERVERS.get());
        return ResultCode.PARAM_ERROR;
      }

      // Next, retrieve the root DSE over each connection.  Use it to verify
      // that both the startupUUID values are different as a check to ensure
      // that the source and target servers are different (this will be a
      // best-effort attempt, so if either startupUUID can't be retrieved, then
      // assume they're different servers).  Also check to see whether the
      // source server supports the suppress referential integrity updates
      // control.
      boolean suppressReferentialIntegrityUpdates = false;
      try
      {
        final RootDSE sourceRootDSE = sourceConnection.getRootDSE();
        final RootDSE targetRootDSE = targetConnection.getRootDSE();

        if ((sourceRootDSE != null) && (targetRootDSE != null))
        {
          final String sourceStartupUUID =
               sourceRootDSE.getAttributeValue(ATTR_STARTUP_UUID);
          final String targetStartupUUID =
               targetRootDSE.getAttributeValue(ATTR_STARTUP_UUID);

          if ((sourceStartupUUID != null) &&
              sourceStartupUUID.equals(targetStartupUUID))
          {
            err(ERR_MOVE_SUBTREE_SAME_SOURCE_AND_TARGET_SERVERS.get());
            return ResultCode.PARAM_ERROR;
          }
        }

        if (sourceRootDSE != null)
        {
          suppressReferentialIntegrityUpdates = sourceRootDSE.supportsControl(
               SuppressReferentialIntegrityUpdatesRequestControl.
                    SUPPRESS_REFINT_REQUEST_OID);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }


      boolean first = true;
      ResultCode resultCode = ResultCode.SUCCESS;
      for (final String dn : baseDNs)
      {
        if (first)
        {
          first = false;
        }
        else
        {
          out();
        }

        final OperationPurposeRequestControl operationPurpose;
        if (purpose.isPresent())
        {
          operationPurpose = new OperationPurposeRequestControl(
               getToolName(), getToolVersion(), 20, purpose.getValue());
        }
        else
        {
          operationPurpose = null;
        }

        final MoveSubtreeResult result = moveSubtreeWithRestrictedAccessibility(
           this, sourceConnection, targetConnection, dn, sizeLimit.getValue(),
             operationPurpose, suppressReferentialIntegrityUpdates,
             (verbose.isPresent() ? this : null));
        if (result.getResultCode() == ResultCode.SUCCESS)
        {
          wrapOut(0, 79,
               INFO_MOVE_SUBTREE_RESULT_SUCCESSFUL.get(
                    result.getEntriesAddedToTarget(), dn));
        }
        else
        {
          if (resultCode == ResultCode.SUCCESS)
          {
            resultCode = result.getResultCode();
          }

          wrapErr(0, 79, ERR_MOVE_SUBTREE_RESULT_UNSUCCESSFUL.get());

          if (result.getErrorMessage() != null)
          {
            wrapErr(0, 79,
                 ERR_MOVE_SUBTREE_ERROR_MESSAGE.get(result.getErrorMessage()));
          }

          if (result.getAdminActionRequired() != null)
          {
            wrapErr(0, 79,
                 ERR_MOVE_SUBTREE_ADMIN_ACTION.get(
                      result.getAdminActionRequired()));
          }
        }
      }

      return resultCode;
    }
    finally
    {
      if (sourceConnection!= null)
      {
        sourceConnection.close();
      }

      if (targetConnection!= null)
      {
        targetConnection.close();
      }
    }
  }



  /**
   * <BLOCKQUOTE>
   *   <B>NOTE:</B>  The use of interactive transactions is strongly discouraged
   *   because it can create conditions which are prone to deadlocks between
   *   operations that may significantly affect performance and will result in
   *   the cancellation of one or both operations.  Use one of the
   *   {@code moveSubtreeWithRestrictedAccessibility} methods instead.
   * </BLOCKQUOTE>
   * Moves a single leaf entry using a pair of interactive transactions.  The
   * logic used to accomplish this is as follows:
   * <OL>
   *   <LI>Start an interactive transaction in the source server.</LI>
   *   <LI>Start an interactive transaction in the target server.</LI>
   *   <LI>Read the entry from the source server.  The search request will have
   *       a subtree scope with a size limit of one, a filter of
   *       "(objectClass=*)", will request all user and operational attributes,
   *       and will include the following request controls:  interactive
   *       transaction specification, ManageDsaIT, LDAP subentries, return
   *       conflict entries, soft-deleted entry access, real attributes only,
   *       and operation purpose.</LI>
   *  <LI>Add the entry to the target server.  The add request will include the
   *      following controls:  interactive transaction specification, ignore
   *      NO-USER-MODIFICATION, and operation purpose.</LI>
   *  <LI>Delete the entry from the source server.  The delete request will
   *      include the following controls:  interactive transaction
   *      specification, ManageDsaIT, and operation purpose.</LI>
   *  <LI>Commit the interactive transaction in the target server.</LI>
   *  <LI>Commit the interactive transaction in the source server.</LI>
   * </OL>
   * Conditions which could result in an incomplete move include:
   * <UL>
   *   <LI>The commit in the target server succeeds but the commit in the
   *       source server fails.  In this case, the entry may end up in both
   *       servers, requiring manual cleanup.  If this occurs, then the result
   *       returned from this method will indicate this condition.</LI>
   *   <LI>The account used to read entries from the source server does not have
   *       permission to see all attributes in all entries.  In this case, the
   *       target server will include only a partial representation of the entry
   *       in the source server.  To avoid this problem, ensure that the account
   *       used to read from the source server has sufficient access rights to
   *       see all attributes in the entry to move.</LI>
   *   <LI>The source server participates in replication and a change occurs to
   *       the entry in a different server in the replicated environment while
   *       the move is in progress.  In this case, those changes may not be
   *       reflected in the target server.  To avoid this problem, it is
   *       strongly recommended that all write access in the replication
   *       environment containing the source server be directed to the source
   *       server during the time that the move is in progress (e.g., using a
   *       failover load-balancing algorithm in the Directory Proxy
   *       Server).</LI>
   * </UL>
   *
   * @param  sourceConnection  A connection established to the source server.
   *                           It should be authenticated as a user with
   *                           permission to perform all of the operations
   *                           against the source server as referenced above.
   * @param  targetConnection  A connection established to the target server.
   *                           It should be authenticated as a user with
   *                           permission to perform all of the operations
   *                           against the target server as referenced above.
   * @param  entryDN           The base DN for the subtree to move.
   * @param  opPurposeControl  An optional operation purpose request control
   *                           that may be included in all requests sent to the
   *                           source and target servers.
   * @param  listener          An optional listener that may be invoked during
   *                           the course of moving entries from the source
   *                           server to the target server.
   *
   * @return  An object with information about the result of the attempted
   *          subtree move.
   *
   * @deprecated  The use of interactive transactions is strongly discouraged
   *              because it can create conditions which are prone to deadlocks
   *              between operations that may significantly affect performance
   *              and will result in the cancellation of one or both operations.
   */
  @Deprecated()
  @NotNull()
  public static MoveSubtreeResult moveEntryWithInteractiveTransaction(
              @NotNull final LDAPConnection sourceConnection,
              @NotNull final LDAPConnection targetConnection,
              @NotNull final String entryDN,
              @Nullable final OperationPurposeRequestControl opPurposeControl,
              @Nullable final MoveSubtreeListener listener)
  {
    return moveEntryWithInteractiveTransaction(sourceConnection,
         targetConnection, entryDN, opPurposeControl, false, listener);
  }



  /**
   * <BLOCKQUOTE>
   *   <B>NOTE:</B>  The use of interactive transactions is strongly discouraged
   *   because it can create conditions which are prone to deadlocks between
   *   operations that may significantly affect performance and will result in
   *   the cancellation of one or both operations.  Use one of the
   *   {@code moveSubtreeWithRestrictedAccessibility} methods instead.
   * </BLOCKQUOTE>
   * Moves a single leaf entry using a pair of interactive transactions.  The
   * logic used to accomplish this is as follows:
   * <OL>
   *   <LI>Start an interactive transaction in the source server.</LI>
   *   <LI>Start an interactive transaction in the target server.</LI>
   *   <LI>Read the entry from the source server.  The search request will have
   *       a subtree scope with a size limit of one, a filter of
   *       "(objectClass=*)", will request all user and operational attributes,
   *       and will include the following request controls:  interactive
   *       transaction specification, ManageDsaIT, LDAP subentries, return
   *       conflict entries, soft-deleted entry access, real attributes only,
   *       and operation purpose.</LI>
   *  <LI>Add the entry to the target server.  The add request will include the
   *      following controls:  interactive transaction specification, ignore
   *      NO-USER-MODIFICATION, and operation purpose.</LI>
   *  <LI>Delete the entry from the source server.  The delete request will
   *      include the following controls:  interactive transaction
   *      specification, ManageDsaIT, and operation purpose.</LI>
   *  <LI>Commit the interactive transaction in the target server.</LI>
   *  <LI>Commit the interactive transaction in the source server.</LI>
   * </OL>
   * Conditions which could result in an incomplete move include:
   * <UL>
   *   <LI>The commit in the target server succeeds but the commit in the
   *       source server fails.  In this case, the entry may end up in both
   *       servers, requiring manual cleanup.  If this occurs, then the result
   *       returned from this method will indicate this condition.</LI>
   *   <LI>The account used to read entries from the source server does not have
   *       permission to see all attributes in all entries.  In this case, the
   *       target server will include only a partial representation of the entry
   *       in the source server.  To avoid this problem, ensure that the account
   *       used to read from the source server has sufficient access rights to
   *       see all attributes in the entry to move.</LI>
   *   <LI>The source server participates in replication and a change occurs to
   *       the entry in a different server in the replicated environment while
   *       the move is in progress.  In this case, those changes may not be
   *       reflected in the target server.  To avoid this problem, it is
   *       strongly recommended that all write access in the replication
   *       environment containing the source server be directed to the source
   *       server during the time that the move is in progress (e.g., using a
   *       failover load-balancing algorithm in the Directory Proxy
   *       Server).</LI>
   * </UL>
   *
   * @param  sourceConnection  A connection established to the source server.
   *                           It should be authenticated as a user with
   *                           permission to perform all of the operations
   *                           against the source server as referenced above.
   * @param  targetConnection  A connection established to the target server.
   *                           It should be authenticated as a user with
   *                           permission to perform all of the operations
   *                           against the target server as referenced above.
   * @param  entryDN           The base DN for the subtree to move.
   * @param  opPurposeControl  An optional operation purpose request control
   *                           that may be included in all requests sent to the
   *                           source and target servers.
   * @param  suppressRefInt    Indicates whether to include a request control
   *                           causing referential integrity updates to be
   *                           suppressed on the source server.
   * @param  listener          An optional listener that may be invoked during
   *                           the course of moving entries from the source
   *                           server to the target server.
   *
   * @return  An object with information about the result of the attempted
   *          subtree move.
   *
   * @deprecated  The use of interactive transactions is strongly discouraged
   *              because it can create conditions which are prone to deadlocks
   *              between operations that may significantly affect performance
   *              and will result in the cancellation of one or both operations.
   */
  @Deprecated()
  @SuppressWarnings("deprecation")
  @NotNull()
  public static MoveSubtreeResult moveEntryWithInteractiveTransaction(
              @NotNull final LDAPConnection sourceConnection,
              @NotNull final LDAPConnection targetConnection,
              @NotNull final String entryDN,
              @Nullable final OperationPurposeRequestControl opPurposeControl,
              final boolean suppressRefInt,
              @Nullable final MoveSubtreeListener listener)
  {
    final StringBuilder errorMsg = new StringBuilder();
    final StringBuilder adminMsg = new StringBuilder();

    final ReverseComparator<DN> reverseComparator = new ReverseComparator<>();
    final TreeSet<DN> sourceEntryDNs = new TreeSet<>(reverseComparator);

    final AtomicInteger entriesReadFromSource    = new AtomicInteger(0);
    final AtomicInteger entriesAddedToTarget     = new AtomicInteger(0);
    final AtomicInteger entriesDeletedFromSource = new AtomicInteger(0);
    final AtomicReference<ResultCode> resultCode = new AtomicReference<>();

    ASN1OctetString sourceTxnID = null;
    ASN1OctetString targetTxnID = null;
    boolean sourceServerAltered = false;
    boolean targetServerAltered = false;

processingBlock:
    try
    {
      // Start an interactive transaction in the source server.
      final com.unboundid.ldap.sdk.unboundidds.controls.
           InteractiveTransactionSpecificationRequestControl sourceTxnControl;
      try
      {
        final com.unboundid.ldap.sdk.unboundidds.extensions.
             StartInteractiveTransactionExtendedRequest startTxnRequest;
        if (opPurposeControl == null)
        {
          startTxnRequest = new com.unboundid.ldap.sdk.unboundidds.extensions.
               StartInteractiveTransactionExtendedRequest(entryDN);
        }
        else
        {
          startTxnRequest = new com.unboundid.ldap.sdk.unboundidds.extensions.
               StartInteractiveTransactionExtendedRequest(entryDN,
               new Control[]{opPurposeControl});
        }

        final com.unboundid.ldap.sdk.unboundidds.extensions.
             StartInteractiveTransactionExtendedResult startTxnResult =
             (com.unboundid.ldap.sdk.unboundidds.extensions.
                  StartInteractiveTransactionExtendedResult)
             sourceConnection.processExtendedOperation(startTxnRequest);
        if (startTxnResult.getResultCode() == ResultCode.SUCCESS)
        {
          sourceTxnID = startTxnResult.getTransactionID();
          sourceTxnControl = new com.unboundid.ldap.sdk.unboundidds.controls.
               InteractiveTransactionSpecificationRequestControl(sourceTxnID,
               true, true);
        }
        else
        {
          resultCode.compareAndSet(null, startTxnResult.getResultCode());
          append(
               ERR_MOVE_ENTRY_CANNOT_START_SOURCE_TXN.get(
                    startTxnResult.getDiagnosticMessage()),
               errorMsg);
          break processingBlock;
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        resultCode.compareAndSet(null, le.getResultCode());
        append(
             ERR_MOVE_ENTRY_CANNOT_START_SOURCE_TXN.get(
                  StaticUtils.getExceptionMessage(le)),
             errorMsg);
        break processingBlock;
      }


      // Start an interactive transaction in the target server.
      final com.unboundid.ldap.sdk.unboundidds.controls.
           InteractiveTransactionSpecificationRequestControl targetTxnControl;
      try
      {
        final com.unboundid.ldap.sdk.unboundidds.extensions.
             StartInteractiveTransactionExtendedRequest startTxnRequest;
        if (opPurposeControl == null)
        {
          startTxnRequest = new com.unboundid.ldap.sdk.unboundidds.extensions.
               StartInteractiveTransactionExtendedRequest(entryDN);
        }
        else
        {
          startTxnRequest = new com.unboundid.ldap.sdk.unboundidds.extensions.
               StartInteractiveTransactionExtendedRequest(entryDN,
               new Control[]{opPurposeControl});
        }

        final com.unboundid.ldap.sdk.unboundidds.extensions.
             StartInteractiveTransactionExtendedResult startTxnResult =
             (com.unboundid.ldap.sdk.unboundidds.extensions.
                  StartInteractiveTransactionExtendedResult)
             targetConnection.processExtendedOperation(startTxnRequest);
        if (startTxnResult.getResultCode() == ResultCode.SUCCESS)
        {
          targetTxnID = startTxnResult.getTransactionID();
          targetTxnControl = new com.unboundid.ldap.sdk.unboundidds.controls.
               InteractiveTransactionSpecificationRequestControl(targetTxnID,
               true, true);
        }
        else
        {
          resultCode.compareAndSet(null, startTxnResult.getResultCode());
          append(
               ERR_MOVE_ENTRY_CANNOT_START_TARGET_TXN.get(
                    startTxnResult.getDiagnosticMessage()),
               errorMsg);
          break processingBlock;
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        resultCode.compareAndSet(null, le.getResultCode());
        append(
             ERR_MOVE_ENTRY_CANNOT_START_TARGET_TXN.get(
                  StaticUtils.getExceptionMessage(le)),
             errorMsg);
        break processingBlock;
      }


      // Perform a search to find all entries in the target subtree, and include
      // a search listener that will add each entry to the target server as it
      // is returned from the source server.
      final Control[] searchControls;
      if (opPurposeControl == null)
      {
        searchControls = new Control[]
        {
          sourceTxnControl,
          new DraftLDUPSubentriesRequestControl(true),
          new ManageDsaITRequestControl(true),
          new ReturnConflictEntriesRequestControl(true),
          new SoftDeletedEntryAccessRequestControl(true, true, false),
          new RealAttributesOnlyRequestControl(true)
        };
      }
      else
      {
        searchControls = new Control[]
        {
          sourceTxnControl,
          new DraftLDUPSubentriesRequestControl(true),
          new ManageDsaITRequestControl(true),
          new ReturnConflictEntriesRequestControl(true),
          new SoftDeletedEntryAccessRequestControl(true, true, false),
          new RealAttributesOnlyRequestControl(true),
          opPurposeControl
        };
      }

      final MoveSubtreeTxnSearchListener searchListener =
           new MoveSubtreeTxnSearchListener(targetConnection, resultCode,
                errorMsg, entriesReadFromSource, entriesAddedToTarget,
                sourceEntryDNs, targetTxnControl, opPurposeControl, listener);
      final SearchRequest searchRequest = new SearchRequest(
           searchListener, searchControls, entryDN, SearchScope.SUB,
           DereferencePolicy.NEVER, 1, 0, false,
           Filter.createPresenceFilter("objectClass"), "*", "+");

      SearchResult searchResult;
      try
      {
        searchResult = sourceConnection.search(searchRequest);
      }
      catch (final LDAPSearchException lse)
      {
        Debug.debugException(lse);
        searchResult = lse.getSearchResult();
      }

      if (searchResult.getResultCode() == ResultCode.SUCCESS)
      {
        try
        {
          final com.unboundid.ldap.sdk.unboundidds.controls.
               InteractiveTransactionSpecificationResponseControl txnResult =
               com.unboundid.ldap.sdk.unboundidds.controls.
                    InteractiveTransactionSpecificationResponseControl.get(
                         searchResult);
          if ((txnResult == null) || (! txnResult.transactionValid()))
          {
            resultCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
            append(ERR_MOVE_ENTRY_SEARCH_TXN_NO_LONGER_VALID.get(),
                 errorMsg);
            break processingBlock;
          }
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          resultCode.compareAndSet(null, le.getResultCode());
          append(
               ERR_MOVE_ENTRY_CANNOT_DECODE_SEARCH_TXN_CONTROL.get(
                    StaticUtils.getExceptionMessage(le)),
               errorMsg);
          break processingBlock;
        }
      }
      else
      {
        resultCode.compareAndSet(null, searchResult.getResultCode());
        append(
             ERR_MOVE_SUBTREE_SEARCH_FAILED.get(entryDN,
                  searchResult.getDiagnosticMessage()),
             errorMsg);

        try
        {
          final com.unboundid.ldap.sdk.unboundidds.controls.
               InteractiveTransactionSpecificationResponseControl txnResult =
               com.unboundid.ldap.sdk.unboundidds.controls.
                    InteractiveTransactionSpecificationResponseControl.get(
                         searchResult);
          if ((txnResult != null) && (! txnResult.transactionValid()))
          {
            sourceTxnID = null;
          }
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
        }

        if (! searchListener.targetTransactionValid())
        {
          targetTxnID = null;
        }

        break processingBlock;
      }

      // If an error occurred during add processing, then fail.
      if (resultCode.get() == null)
      {
        targetServerAltered = true;
      }
      else
      {
        break processingBlock;
      }


      // Delete each of the entries in the source server.  The map should
      // already be sorted in reverse order (as a result of the comparator used
      // when creating it), so it will guarantee children are deleted before
      // their parents.
      final ArrayList<Control> deleteControlList = new ArrayList<>(4);
      deleteControlList.add(sourceTxnControl);
      deleteControlList.add(new ManageDsaITRequestControl(true));
      if (opPurposeControl != null)
      {
        deleteControlList.add(opPurposeControl);
      }
      if (suppressRefInt)
      {
        deleteControlList.add(
             new SuppressReferentialIntegrityUpdatesRequestControl(false));
      }

      final Control[] deleteControls = new Control[deleteControlList.size()];
      deleteControlList.toArray(deleteControls);
      for (final DN dn : sourceEntryDNs)
      {
        if (listener != null)
        {
          try
          {
            listener.doPreDeleteProcessing(dn);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            resultCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
            append(
                 ERR_MOVE_SUBTREE_PRE_DELETE_FAILURE.get(dn.toString(),
                      StaticUtils.getExceptionMessage(e)),
                 errorMsg);
            break processingBlock;
          }
        }

        LDAPResult deleteResult;
        try
        {
          deleteResult = sourceConnection.delete(
               new DeleteRequest(dn, deleteControls));
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          deleteResult = le.toLDAPResult();
        }

        if (deleteResult.getResultCode() == ResultCode.SUCCESS)
        {
          sourceServerAltered = true;
          entriesDeletedFromSource.incrementAndGet();

          try
          {
            final com.unboundid.ldap.sdk.unboundidds.controls.
                 InteractiveTransactionSpecificationResponseControl txnResult =
                 com.unboundid.ldap.sdk.unboundidds.controls.
                      InteractiveTransactionSpecificationResponseControl.get(
                           deleteResult);
            if ((txnResult == null) || (! txnResult.transactionValid()))
            {
              resultCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
              append(
                   ERR_MOVE_ENTRY_DELETE_TXN_NO_LONGER_VALID.get(
                        dn.toString()),
                   errorMsg);
              break processingBlock;
            }
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            resultCode.compareAndSet(null, le.getResultCode());
            append(
                 ERR_MOVE_ENTRY_CANNOT_DECODE_DELETE_TXN_CONTROL.get(
                      dn.toString(), StaticUtils.getExceptionMessage(le)),
                 errorMsg);
            break processingBlock;
          }
        }
        else
        {
          resultCode.compareAndSet(null, deleteResult.getResultCode());
          append(
               ERR_MOVE_SUBTREE_DELETE_FAILURE.get(
                    dn.toString(), deleteResult.getDiagnosticMessage()),
               errorMsg);

          try
          {
            final com.unboundid.ldap.sdk.unboundidds.controls.
                 InteractiveTransactionSpecificationResponseControl txnResult =
                 com.unboundid.ldap.sdk.unboundidds.controls.
                      InteractiveTransactionSpecificationResponseControl.get(
                           deleteResult);
            if ((txnResult != null) && (! txnResult.transactionValid()))
            {
              sourceTxnID = null;
            }
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
          }

          break processingBlock;
        }

        if (listener != null)
        {
          try
          {
            listener.doPostDeleteProcessing(dn);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            resultCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
            append(
                 ERR_MOVE_SUBTREE_POST_DELETE_FAILURE.get(dn.toString(),
                      StaticUtils.getExceptionMessage(e)),
                 errorMsg);
            break processingBlock;
          }
        }
      }


      // Commit the transaction in the target server.
      try
      {
        final com.unboundid.ldap.sdk.unboundidds.extensions.
             EndInteractiveTransactionExtendedRequest commitRequest;
        if (opPurposeControl == null)
        {
          commitRequest = new com.unboundid.ldap.sdk.unboundidds.extensions.
               EndInteractiveTransactionExtendedRequest(targetTxnID, true);
        }
        else
        {
          commitRequest = new com.unboundid.ldap.sdk.unboundidds.extensions.
               EndInteractiveTransactionExtendedRequest(targetTxnID, true,
               new Control[] { opPurposeControl });
        }

        final ExtendedResult commitResult =
             targetConnection.processExtendedOperation(commitRequest);
        if (commitResult.getResultCode() == ResultCode.SUCCESS)
        {
          targetTxnID = null;
        }
        else
        {
          resultCode.compareAndSet(null, commitResult.getResultCode());
          append(
               ERR_MOVE_ENTRY_CANNOT_COMMIT_TARGET_TXN.get(
                    commitResult.getDiagnosticMessage()),
               errorMsg);
          break processingBlock;
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        resultCode.compareAndSet(null, le.getResultCode());
        append(
             ERR_MOVE_ENTRY_CANNOT_COMMIT_TARGET_TXN.get(
                  StaticUtils.getExceptionMessage(le)),
             errorMsg);
        break processingBlock;
      }


      // Commit the transaction in the source server.
      try
      {
        final com.unboundid.ldap.sdk.unboundidds.extensions.
             EndInteractiveTransactionExtendedRequest commitRequest;
        if (opPurposeControl == null)
        {
          commitRequest = new com.unboundid.ldap.sdk.unboundidds.extensions.
               EndInteractiveTransactionExtendedRequest(sourceTxnID, true);
        }
        else
        {
          commitRequest = new com.unboundid.ldap.sdk.unboundidds.extensions.
               EndInteractiveTransactionExtendedRequest(sourceTxnID, true,
               new Control[] { opPurposeControl });
        }

        final ExtendedResult commitResult =
             sourceConnection.processExtendedOperation(commitRequest);
        if (commitResult.getResultCode() == ResultCode.SUCCESS)
        {
          sourceTxnID = null;
        }
        else
        {
          resultCode.compareAndSet(null, commitResult.getResultCode());
          append(
               ERR_MOVE_ENTRY_CANNOT_COMMIT_SOURCE_TXN.get(
                    commitResult.getDiagnosticMessage()),
               errorMsg);
          break processingBlock;
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        resultCode.compareAndSet(null, le.getResultCode());
        append(
             ERR_MOVE_ENTRY_CANNOT_COMMIT_SOURCE_TXN.get(
                  StaticUtils.getExceptionMessage(le)),
             errorMsg);
        append(ERR_MOVE_ENTRY_EXISTS_IN_BOTH_SERVERS.get(entryDN),
             adminMsg);
        break processingBlock;
      }
    }
    finally
    {
      // If the transaction is still active in the target server, then abort it.
      if (targetTxnID != null)
      {
        try
        {
          final com.unboundid.ldap.sdk.unboundidds.extensions.
               EndInteractiveTransactionExtendedRequest abortRequest;
          if (opPurposeControl == null)
          {
            abortRequest = new com.unboundid.ldap.sdk.unboundidds.extensions.
                 EndInteractiveTransactionExtendedRequest(targetTxnID, false);
          }
          else
          {
            abortRequest = new com.unboundid.ldap.sdk.unboundidds.extensions.
                 EndInteractiveTransactionExtendedRequest(targetTxnID, false,
                 new Control[] { opPurposeControl });
          }

          final ExtendedResult abortResult =
               targetConnection.processExtendedOperation(abortRequest);
          if (abortResult.getResultCode() ==
                   ResultCode.INTERACTIVE_TRANSACTION_ABORTED)
          {
            targetServerAltered = false;
            entriesAddedToTarget.set(0);
            append(INFO_MOVE_ENTRY_TARGET_ABORT_SUCCEEDED.get(),
                 errorMsg);
          }
          else
          {
            append(
                 ERR_MOVE_ENTRY_TARGET_ABORT_FAILURE.get(
                      abortResult.getDiagnosticMessage()),
                 errorMsg);
            append(
                 ERR_MOVE_ENTRY_TARGET_ABORT_FAILURE_ADMIN_ACTION.get(
                      entryDN),
                 adminMsg);
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          append(
               ERR_MOVE_ENTRY_TARGET_ABORT_FAILURE.get(
                    StaticUtils.getExceptionMessage(e)),
               errorMsg);
          append(
               ERR_MOVE_ENTRY_TARGET_ABORT_FAILURE_ADMIN_ACTION.get(
                    entryDN),
               adminMsg);
        }
      }


      // If the transaction is still active in the source server, then abort it.
      if (sourceTxnID != null)
      {
        try
        {
          final com.unboundid.ldap.sdk.unboundidds.extensions.
               EndInteractiveTransactionExtendedRequest abortRequest;
          if (opPurposeControl == null)
          {
            abortRequest = new com.unboundid.ldap.sdk.unboundidds.extensions.
                 EndInteractiveTransactionExtendedRequest(sourceTxnID, false);
          }
          else
          {
            abortRequest = new com.unboundid.ldap.sdk.unboundidds.extensions.
                 EndInteractiveTransactionExtendedRequest(sourceTxnID, false,
                 new Control[] { opPurposeControl });
          }

          final ExtendedResult abortResult =
               sourceConnection.processExtendedOperation(abortRequest);
          if (abortResult.getResultCode() ==
                   ResultCode.INTERACTIVE_TRANSACTION_ABORTED)
          {
            sourceServerAltered = false;
            entriesDeletedFromSource.set(0);
            append(INFO_MOVE_ENTRY_SOURCE_ABORT_SUCCEEDED.get(),
                 errorMsg);
          }
          else
          {
            append(
                 ERR_MOVE_ENTRY_SOURCE_ABORT_FAILURE.get(
                      abortResult.getDiagnosticMessage()),
                 errorMsg);
            append(
                 ERR_MOVE_ENTRY_SOURCE_ABORT_FAILURE_ADMIN_ACTION.get(
                      entryDN),
                 adminMsg);
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          append(
               ERR_MOVE_ENTRY_SOURCE_ABORT_FAILURE.get(
                    StaticUtils.getExceptionMessage(e)),
               errorMsg);
          append(
               ERR_MOVE_ENTRY_SOURCE_ABORT_FAILURE_ADMIN_ACTION.get(
                    entryDN),
               adminMsg);
        }
      }
    }


    // Construct the result to return to the client.
    resultCode.compareAndSet(null, ResultCode.SUCCESS);

    final String errorMessage;
    if (errorMsg.length() > 0)
    {
      errorMessage = errorMsg.toString();
    }
    else
    {
      errorMessage = null;
    }

    final String adminActionRequired;
    if (adminMsg.length() > 0)
    {
      adminActionRequired = adminMsg.toString();
    }
    else
    {
      adminActionRequired = null;
    }

    return new MoveSubtreeResult(resultCode.get(), errorMessage,
         adminActionRequired, sourceServerAltered, targetServerAltered,
         entriesReadFromSource.get(), entriesAddedToTarget.get(),
         entriesDeletedFromSource.get());
  }



  /**
   * Moves a subtree of entries using a process in which access to the subtree
   * will be restricted while the move is in progress.  While entries are being
   * read from the source server and added to the target server, the subtree
   * will be read-only in the source server and hidden in the target server.
   * While entries are being removed from the source server, the subtree will be
   * hidden in the source server while fully accessible in the target.  After
   * all entries have been removed from the source server, the accessibility
   * restriction will be removed from that server as well.
   * <BR><BR>
   * The logic used to accomplish this is as follows:
   * <OL>
   *   <LI>Make the subtree hidden in the target server.</LI>
   *   <LI>Make the subtree read-only in the source server.</LI>
   *   <LI>Perform a search in the source server to retrieve all entries in the
   *       specified subtree.  The search request will have a subtree scope with
   *       a filter of "(objectClass=*)", will include the specified size limit,
   *       will request all user and operational attributes, and will include
   *       the following request controls:  ManageDsaIT, LDAP subentries,
   *       return conflict entries, soft-deleted entry access, real attributes
   *       only, and operation purpose.</LI>
   *  <LI>For each entry returned by the search, add that entry to the target
   *      server.  This method assumes that the source server will return
   *      results in a manner that guarantees that no child entry is returned
   *      before its parent.  Each add request will include the following
   *      controls:  ignore NO-USER-MODIFICATION, and operation purpose.</LI>
   *  <LI>Make the subtree read-only in the target server.</LI>
   *  <LI>Make the subtree hidden in the source server.</LI>
   *  <LI>Make the subtree accessible in the target server.</LI>
   *  <LI>Delete each entry from the source server, with all subordinate entries
   *      before their parents.  Each delete request will include the following
   *      controls:  ManageDsaIT, and operation purpose.</LI>
   *  <LI>Make the subtree accessible in the source server.</LI>
   * </OL>
   * Conditions which could result in an incomplete move include:
   * <UL>
   *   <LI>A failure is encountered while altering the accessibility of the
   *       subtree in either the source or target server.</LI>
   *   <LI>A failure is encountered while attempting to process an add in the
   *       target server and a subsequent failure is encountered when attempting
   *       to delete previously-added entries.</LI>
   *   <LI>A failure is encountered while attempting to delete one or more
   *       entries from the source server.</LI>
   * </UL>
   *
   * @param  sourceConnection  A connection established to the source server.
   *                           It should be authenticated as a user with
   *                           permission to perform all of the operations
   *                           against the source server as referenced above.
   * @param  targetConnection  A connection established to the target server.
   *                           It should be authenticated as a user with
   *                           permission to perform all of the operations
   *                           against the target server as referenced above.
   * @param  baseDN            The base DN for the subtree to move.
   * @param  sizeLimit         The maximum number of entries to be moved.  It
   *                           may be less than or equal to zero to indicate
   *                           that no client-side limit should be enforced
   *                           (although the server may still enforce its own
   *                           limit).
   * @param  opPurposeControl  An optional operation purpose request control
   *                           that may be included in all requests sent to the
   *                           source and target servers.
   * @param  listener          An optional listener that may be invoked during
   *                           the course of moving entries from the source
   *                           server to the target server.
   *
   * @return  An object with information about the result of the attempted
   *          subtree move.
   */
  @NotNull()
  public static MoveSubtreeResult moveSubtreeWithRestrictedAccessibility(
              @NotNull final LDAPConnection sourceConnection,
              @NotNull final LDAPConnection targetConnection,
              @NotNull final String baseDN, final int sizeLimit,
              @Nullable final OperationPurposeRequestControl opPurposeControl,
              @Nullable final MoveSubtreeListener listener)
  {
    return moveSubtreeWithRestrictedAccessibility(sourceConnection,
         targetConnection, baseDN, sizeLimit, opPurposeControl, false,
         listener);
  }



  /**
   * Moves a subtree of entries using a process in which access to the subtree
   * will be restricted while the move is in progress.  While entries are being
   * read from the source server and added to the target server, the subtree
   * will be read-only in the source server and hidden in the target server.
   * While entries are being removed from the source server, the subtree will be
   * hidden in the source server while fully accessible in the target.  After
   * all entries have been removed from the source server, the accessibility
   * restriction will be removed from that server as well.
   * <BR><BR>
   * The logic used to accomplish this is as follows:
   * <OL>
   *   <LI>Make the subtree hidden in the target server.</LI>
   *   <LI>Make the subtree read-only in the source server.</LI>
   *   <LI>Perform a search in the source server to retrieve all entries in the
   *       specified subtree.  The search request will have a subtree scope with
   *       a filter of "(objectClass=*)", will include the specified size limit,
   *       will request all user and operational attributes, and will include
   *       the following request controls:  ManageDsaIT, LDAP subentries,
   *       return conflict entries, soft-deleted entry access, real attributes
   *       only, and operation purpose.</LI>
   *  <LI>For each entry returned by the search, add that entry to the target
   *      server.  This method assumes that the source server will return
   *      results in a manner that guarantees that no child entry is returned
   *      before its parent.  Each add request will include the following
   *      controls:  ignore NO-USER-MODIFICATION, and operation purpose.</LI>
   *  <LI>Make the subtree read-only in the target server.</LI>
   *  <LI>Make the subtree hidden in the source server.</LI>
   *  <LI>Make the subtree accessible in the target server.</LI>
   *  <LI>Delete each entry from the source server, with all subordinate entries
   *      before their parents.  Each delete request will include the following
   *      controls:  ManageDsaIT, and operation purpose.</LI>
   *  <LI>Make the subtree accessible in the source server.</LI>
   * </OL>
   * Conditions which could result in an incomplete move include:
   * <UL>
   *   <LI>A failure is encountered while altering the accessibility of the
   *       subtree in either the source or target server.</LI>
   *   <LI>A failure is encountered while attempting to process an add in the
   *       target server and a subsequent failure is encountered when attempting
   *       to delete previously-added entries.</LI>
   *   <LI>A failure is encountered while attempting to delete one or more
   *       entries from the source server.</LI>
   * </UL>
   *
   * @param  sourceConnection  A connection established to the source server.
   *                           It should be authenticated as a user with
   *                           permission to perform all of the operations
   *                           against the source server as referenced above.
   * @param  targetConnection  A connection established to the target server.
   *                           It should be authenticated as a user with
   *                           permission to perform all of the operations
   *                           against the target server as referenced above.
   * @param  baseDN            The base DN for the subtree to move.
   * @param  sizeLimit         The maximum number of entries to be moved.  It
   *                           may be less than or equal to zero to indicate
   *                           that no client-side limit should be enforced
   *                           (although the server may still enforce its own
   *                           limit).
   * @param  opPurposeControl  An optional operation purpose request control
   *                           that may be included in all requests sent to the
   *                           source and target servers.
   * @param  suppressRefInt    Indicates whether to include a request control
   *                           causing referential integrity updates to be
   *                           suppressed on the source server.
   * @param  listener          An optional listener that may be invoked during
   *                           the course of moving entries from the source
   *                           server to the target server.
   *
   * @return  An object with information about the result of the attempted
   *          subtree move.
   */
  @NotNull()
  public static MoveSubtreeResult moveSubtreeWithRestrictedAccessibility(
              @NotNull final LDAPConnection sourceConnection,
              @NotNull final LDAPConnection targetConnection,
              @NotNull final String baseDN, final int sizeLimit,
              @Nullable final OperationPurposeRequestControl opPurposeControl,
              final boolean suppressRefInt,
              @Nullable final MoveSubtreeListener listener)
  {
    return moveSubtreeWithRestrictedAccessibility(null, sourceConnection,
         targetConnection, baseDN, sizeLimit, opPurposeControl, suppressRefInt,
         listener);
  }



  /**
   * Performs the real {@code moveSubtreeWithRestrictedAccessibility}
   * processing.  If a tool is available, this method will update state
   * information in that tool so that it can be referenced by a shutdown hook
   * in the event that processing is interrupted.
   *
   * @param  tool              A reference to a tool instance to be updated with
   *                           state information.
   * @param  sourceConnection  A connection established to the source server.
   *                           It should be authenticated as a user with
   *                           permission to perform all of the operations
   *                           against the source server as referenced above.
   * @param  targetConnection  A connection established to the target server.
   *                           It should be authenticated as a user with
   *                           permission to perform all of the operations
   *                           against the target server as referenced above.
   * @param  baseDN            The base DN for the subtree to move.
   * @param  sizeLimit         The maximum number of entries to be moved.  It
   *                           may be less than or equal to zero to indicate
   *                           that no client-side limit should be enforced
   *                           (although the server may still enforce its own
   *                           limit).
   * @param  opPurposeControl  An optional operation purpose request control
   *                           that may be included in all requests sent to the
   *                           source and target servers.
   * @param  suppressRefInt    Indicates whether to include a request control
   *                           causing referential integrity updates to be
   *                           suppressed on the source server.
   * @param  listener          An optional listener that may be invoked during
   *                           the course of moving entries from the source
   *                           server to the target server.
   *
   * @return  An object with information about the result of the attempted
   *          subtree move.
   */
  @NotNull()
  private static MoveSubtreeResult moveSubtreeWithRestrictedAccessibility(
               @Nullable final MoveSubtree tool,
               @NotNull final LDAPConnection sourceConnection,
               @NotNull final LDAPConnection targetConnection,
               @NotNull final String baseDN, final int sizeLimit,
               @Nullable final OperationPurposeRequestControl opPurposeControl,
               final boolean suppressRefInt,
               @Nullable final MoveSubtreeListener listener)
  {
    // Ensure that the subtree is currently accessible in both the source and
    // target servers.
    final MoveSubtreeResult initialAccessibilityResult =
         checkInitialAccessibility(sourceConnection, targetConnection, baseDN,
              opPurposeControl);
    if (initialAccessibilityResult != null)
    {
      return initialAccessibilityResult;
    }


    final StringBuilder errorMsg = new StringBuilder();
    final StringBuilder adminMsg = new StringBuilder();

    final ReverseComparator<DN> reverseComparator = new ReverseComparator<>();
    final TreeSet<DN> sourceEntryDNs = new TreeSet<>(reverseComparator);

    final AtomicInteger entriesReadFromSource    = new AtomicInteger(0);
    final AtomicInteger entriesAddedToTarget     = new AtomicInteger(0);
    final AtomicInteger entriesDeletedFromSource = new AtomicInteger(0);
    final AtomicReference<ResultCode> resultCode = new AtomicReference<>();

    boolean sourceServerAltered = false;
    boolean targetServerAltered = false;

    SubtreeAccessibilityState currentSourceState =
         SubtreeAccessibilityState.ACCESSIBLE;
    SubtreeAccessibilityState currentTargetState =
         SubtreeAccessibilityState.ACCESSIBLE;

processingBlock:
    {
      // Identify the users authenticated on each connection.
      final String sourceUserDN;
      final String targetUserDN;
      try
      {
        sourceUserDN = getAuthenticatedUserDN(sourceConnection, true,
             opPurposeControl);
        targetUserDN = getAuthenticatedUserDN(targetConnection, false,
             opPurposeControl);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        resultCode.compareAndSet(null, le.getResultCode());
        append(le.getMessage(), errorMsg);
        break processingBlock;
      }


      // Make the subtree hidden on the target server.
      try
      {
        setAccessibility(targetConnection, false, baseDN,
             SubtreeAccessibilityState.HIDDEN, targetUserDN, opPurposeControl);
        currentTargetState = SubtreeAccessibilityState.HIDDEN;
        setInterruptMessage(tool,
             WARN_MOVE_SUBTREE_INTERRUPT_MSG_TARGET_HIDDEN.get(baseDN,
                  targetConnection.getConnectedAddress(),
                  targetConnection.getConnectedPort()));
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        resultCode.compareAndSet(null, le.getResultCode());
        append(le.getMessage(), errorMsg);
        break processingBlock;
      }


      // Make the subtree read-only on the source server.
      try
      {
        setAccessibility(sourceConnection, true, baseDN,
             SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED, sourceUserDN,
             opPurposeControl);
        currentSourceState = SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED;
        setInterruptMessage(tool,
             WARN_MOVE_SUBTREE_INTERRUPT_MSG_SOURCE_READ_ONLY.get(baseDN,
                  targetConnection.getConnectedAddress(),
                  targetConnection.getConnectedPort(),
                  sourceConnection.getConnectedAddress(),
                  sourceConnection.getConnectedPort()));
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        resultCode.compareAndSet(null, le.getResultCode());
        append(le.getMessage(), errorMsg);
        break processingBlock;
      }


      // Perform a search to find all entries in the target subtree, and include
      // a search listener that will add each entry to the target server as it
      // is returned from the source server.
      final Control[] searchControls;
      if (opPurposeControl == null)
      {
        searchControls = new Control[]
        {
          new DraftLDUPSubentriesRequestControl(true),
          new ManageDsaITRequestControl(true),
          new ReturnConflictEntriesRequestControl(true),
          new SoftDeletedEntryAccessRequestControl(true, true, false),
          new RealAttributesOnlyRequestControl(true)
        };
      }
      else
      {
        searchControls = new Control[]
        {
          new DraftLDUPSubentriesRequestControl(true),
          new ManageDsaITRequestControl(true),
          new ReturnConflictEntriesRequestControl(true),
          new SoftDeletedEntryAccessRequestControl(true, true, false),
          new RealAttributesOnlyRequestControl(true),
          opPurposeControl
        };
      }

      final MoveSubtreeAccessibilitySearchListener searchListener =
           new MoveSubtreeAccessibilitySearchListener(tool, baseDN,
                sourceConnection, targetConnection, resultCode, errorMsg,
                entriesReadFromSource, entriesAddedToTarget, sourceEntryDNs,
                opPurposeControl, listener);
      final SearchRequest searchRequest = new SearchRequest(
           searchListener, searchControls, baseDN, SearchScope.SUB,
           DereferencePolicy.NEVER, sizeLimit, 0, false,
           Filter.createPresenceFilter("objectClass"), "*", "+");

      SearchResult searchResult;
      try
      {
        searchResult = sourceConnection.search(searchRequest);
      }
      catch (final LDAPSearchException lse)
      {
        Debug.debugException(lse);
        searchResult = lse.getSearchResult();
      }

      if (entriesAddedToTarget.get() > 0)
      {
        targetServerAltered = true;
      }

      if (searchResult.getResultCode() != ResultCode.SUCCESS)
      {
        resultCode.compareAndSet(null, searchResult.getResultCode());
        append(
             ERR_MOVE_SUBTREE_SEARCH_FAILED.get(baseDN,
                  searchResult.getDiagnosticMessage()),
             errorMsg);

        final AtomicInteger deleteCount = new AtomicInteger(0);
        if (targetServerAltered)
        {
          deleteEntries(targetConnection, false, sourceEntryDNs,
               opPurposeControl, false, null, deleteCount, resultCode,
               errorMsg);
          entriesAddedToTarget.addAndGet(0 - deleteCount.get());
          if (entriesAddedToTarget.get() == 0)
          {
            targetServerAltered = false;
          }
          else
          {
            append(ERR_MOVE_SUBTREE_TARGET_NOT_DELETED_ADMIN_ACTION.get(baseDN),
                 adminMsg);
          }
        }
        break processingBlock;
      }

      // If an error occurred during add processing, then fail.
      if (resultCode.get() != null)
      {
        final AtomicInteger deleteCount = new AtomicInteger(0);
        if (targetServerAltered)
        {
          deleteEntries(targetConnection, false, sourceEntryDNs,
               opPurposeControl, false, null, deleteCount, resultCode,
               errorMsg);
          entriesAddedToTarget.addAndGet(0 - deleteCount.get());
          if (entriesAddedToTarget.get() == 0)
          {
            targetServerAltered = false;
          }
          else
          {
            append(ERR_MOVE_SUBTREE_TARGET_NOT_DELETED_ADMIN_ACTION.get(baseDN),
                 adminMsg);
          }
        }
        break processingBlock;
      }


      // Make the subtree read-only on the target server.
      try
      {
        setAccessibility(targetConnection, true, baseDN,
             SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED, targetUserDN,
             opPurposeControl);
        currentTargetState = SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED;
        setInterruptMessage(tool,
             WARN_MOVE_SUBTREE_INTERRUPT_MSG_TARGET_READ_ONLY.get(baseDN,
                  sourceConnection.getConnectedAddress(),
                  sourceConnection.getConnectedPort(),
                  targetConnection.getConnectedAddress(),
                  targetConnection.getConnectedPort()));
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        resultCode.compareAndSet(null, le.getResultCode());
        append(le.getMessage(), errorMsg);
        break processingBlock;
      }


      // Make the subtree hidden on the source server.
      try
      {
        setAccessibility(sourceConnection, true, baseDN,
             SubtreeAccessibilityState.HIDDEN, sourceUserDN,
             opPurposeControl);
        currentSourceState = SubtreeAccessibilityState.HIDDEN;
        setInterruptMessage(tool,
             WARN_MOVE_SUBTREE_INTERRUPT_MSG_SOURCE_HIDDEN.get(baseDN,
                  sourceConnection.getConnectedAddress(),
                  sourceConnection.getConnectedPort(),
                  targetConnection.getConnectedAddress(),
                  targetConnection.getConnectedPort()));
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        resultCode.compareAndSet(null, le.getResultCode());
        append(le.getMessage(), errorMsg);
        break processingBlock;
      }


      // Make the subtree accessible on the target server.
      try
      {
        setAccessibility(targetConnection, true, baseDN,
             SubtreeAccessibilityState.ACCESSIBLE, targetUserDN,
             opPurposeControl);
        currentTargetState = SubtreeAccessibilityState.ACCESSIBLE;
        setInterruptMessage(tool,
             WARN_MOVE_SUBTREE_INTERRUPT_MSG_TARGET_ACCESSIBLE.get(baseDN,
                  sourceConnection.getConnectedAddress(),
                  sourceConnection.getConnectedPort(),
                  targetConnection.getConnectedAddress(),
                  targetConnection.getConnectedPort()));
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        resultCode.compareAndSet(null, le.getResultCode());
        append(le.getMessage(), errorMsg);
        break processingBlock;
      }


      // Delete each of the entries in the source server.  The map should
      // already be sorted in reverse order (as a result of the comparator used
      // when creating it), so it will guarantee children are deleted before
      // their parents.
      final boolean deleteSuccessful = deleteEntries(sourceConnection, true,
           sourceEntryDNs, opPurposeControl, suppressRefInt, listener,
           entriesDeletedFromSource, resultCode, errorMsg);
      sourceServerAltered = (entriesDeletedFromSource.get() != 0);
      if (! deleteSuccessful)
      {
        append(ERR_MOVE_SUBTREE_SOURCE_NOT_DELETED_ADMIN_ACTION.get(baseDN),
             adminMsg);
        break processingBlock;
      }


      // Make the subtree accessible on the source server.
      try
      {
        setAccessibility(sourceConnection, true, baseDN,
             SubtreeAccessibilityState.ACCESSIBLE, sourceUserDN,
             opPurposeControl);
        currentSourceState = SubtreeAccessibilityState.ACCESSIBLE;
        setInterruptMessage(tool, null);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        resultCode.compareAndSet(null, le.getResultCode());
        append(le.getMessage(), errorMsg);
        break processingBlock;
      }
    }


    // If the source server was left in a state other than accessible, then
    // see if we can safely change it back.  If it's left in any state other
    // then accessible, then generate an admin action message.
    if (currentSourceState != SubtreeAccessibilityState.ACCESSIBLE)
    {
      if (! sourceServerAltered)
      {
        try
        {
          setAccessibility(sourceConnection, true, baseDN,
               SubtreeAccessibilityState.ACCESSIBLE, null, opPurposeControl);
          currentSourceState = SubtreeAccessibilityState.ACCESSIBLE;
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
        }
      }

      if (currentSourceState != SubtreeAccessibilityState.ACCESSIBLE)
      {
        append(
             ERR_MOVE_SUBTREE_SOURCE_LEFT_INACCESSIBLE.get(
                  currentSourceState, baseDN),
             adminMsg);
      }
    }


    // If the target server was left in a state other than accessible, then
    // see if we can safely change it back.  If it's left in any state other
    // then accessible, then generate an admin action message.
    if (currentTargetState != SubtreeAccessibilityState.ACCESSIBLE)
    {
      if (! targetServerAltered)
      {
        try
        {
          setAccessibility(targetConnection, false, baseDN,
               SubtreeAccessibilityState.ACCESSIBLE, null, opPurposeControl);
          currentTargetState = SubtreeAccessibilityState.ACCESSIBLE;
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
        }
      }

      if (currentTargetState != SubtreeAccessibilityState.ACCESSIBLE)
      {
        append(
             ERR_MOVE_SUBTREE_TARGET_LEFT_INACCESSIBLE.get(
                  currentTargetState, baseDN),
             adminMsg);
      }
    }


    // Construct the result to return to the client.
    resultCode.compareAndSet(null, ResultCode.SUCCESS);

    final String errorMessage;
    if (errorMsg.length() > 0)
    {
      errorMessage = errorMsg.toString();
    }
    else
    {
      errorMessage = null;
    }

    final String adminActionRequired;
    if (adminMsg.length() > 0)
    {
      adminActionRequired = adminMsg.toString();
    }
    else
    {
      adminActionRequired = null;
    }

    return new MoveSubtreeResult(resultCode.get(), errorMessage,
         adminActionRequired, sourceServerAltered, targetServerAltered,
         entriesReadFromSource.get(), entriesAddedToTarget.get(),
         entriesDeletedFromSource.get());
  }



  /**
   * Retrieves the DN of the user authenticated on the provided connection.  It
   * will first try to look at the last successful bind request processed on the
   * connection, and will fall back to using the "Who Am I?" extended request.
   *
   * @param  connection        The connection for which to make the
   *                           determination.
   * @param  isSource          Indicates whether the connection is to the source
   *                           or target server.
   * @param  opPurposeControl  An optional operation purpose request control
   *                           that may be included in the request.
   *
   * @return  The DN of the user authenticated on the provided connection, or
   *          {@code null} if the connection is not authenticated.
   *
   * @throws  LDAPException  If a problem is encountered while making the
   *                         determination.
   */
  @Nullable()
  private static String getAuthenticatedUserDN(
               @NotNull final LDAPConnection connection,
               final boolean isSource,
               @Nullable final OperationPurposeRequestControl opPurposeControl)
          throws LDAPException
  {
    final BindRequest bindRequest =
         InternalSDKHelper.getLastBindRequest(connection);
    if ((bindRequest != null) && (bindRequest instanceof SimpleBindRequest))
    {
      final SimpleBindRequest r = (SimpleBindRequest) bindRequest;
      return r.getBindDN();
    }


    final Control[] controls;
    if (opPurposeControl == null)
    {
      controls = StaticUtils.NO_CONTROLS;
    }
    else
    {
      controls = new Control[]
      {
        opPurposeControl
      };
    }

    final String connectionName =
         isSource
         ? INFO_MOVE_SUBTREE_CONNECTION_NAME_SOURCE.get()
         : INFO_MOVE_SUBTREE_CONNECTION_NAME_TARGET.get();

    final WhoAmIExtendedResult whoAmIResult;
    try
    {
      whoAmIResult = (WhoAmIExtendedResult)
           connection.processExtendedOperation(
                new WhoAmIExtendedRequest(controls));
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new LDAPException(le.getResultCode(),
           ERR_MOVE_SUBTREE_ERROR_INVOKING_WHO_AM_I.get(connectionName,
                StaticUtils.getExceptionMessage(le)),
           le);
    }

    if (whoAmIResult.getResultCode() != ResultCode.SUCCESS)
    {
      throw new LDAPException(whoAmIResult.getResultCode(),
           ERR_MOVE_SUBTREE_ERROR_INVOKING_WHO_AM_I.get(connectionName,
                whoAmIResult.getDiagnosticMessage()));
    }

    final String authzID = whoAmIResult.getAuthorizationID();
    if ((authzID != null) && authzID.startsWith("dn:"))
    {
      return authzID.substring(3);
    }
    else
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           ERR_MOVE_SUBTREE_CANNOT_IDENTIFY_CONNECTED_USER.get(connectionName));
    }
  }



  /**
   * Ensures that the specified subtree is accessible in both the source and
   * target servers.  If it is not accessible, then it may indicate that another
   * administrative operation is in progress for the subtree, or that a previous
   * move-subtree operation was interrupted before it could complete.
   *
   * @param  sourceConnection  The connection to use to communicate with the
   *                           source directory server.
   * @param  targetConnection  The connection to use to communicate with the
   *                           target directory server.
   * @param  baseDN            The base DN for which to verify accessibility.
   * @param  opPurposeControl  An optional operation purpose request control
   *                           that may be included in the requests.
   *
   * @return  {@code null} if the specified subtree is accessible in both the
   *          source and target servers, or a non-{@code null} object with the
   *          result that should be used if there is an accessibility problem
   *          with the subtree on the source and/or target server.
   */
  @Nullable()
  private static MoveSubtreeResult checkInitialAccessibility(
               @NotNull final LDAPConnection sourceConnection,
               @NotNull final LDAPConnection targetConnection,
               @NotNull final String baseDN,
               @Nullable final OperationPurposeRequestControl opPurposeControl)
  {
    final DN parsedBaseDN;
    try
    {
      parsedBaseDN = new DN(baseDN);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return new MoveSubtreeResult(ResultCode.INVALID_DN_SYNTAX,
           ERR_MOVE_SUBTREE_CANNOT_PARSE_BASE_DN.get(baseDN,
                StaticUtils.getExceptionMessage(e)),
           null, false, false, 0, 0, 0);
    }

    final Control[] controls;
    if (opPurposeControl == null)
    {
      controls = StaticUtils.NO_CONTROLS;
    }
    else
    {
      controls = new Control[]
      {
        opPurposeControl
      };
    }


    // Get the restrictions from the source server.  If there are any, then
    // make sure that nothing in the hierarchy of the base DN is non-accessible.
    final GetSubtreeAccessibilityExtendedResult sourceResult;
    try
    {
      sourceResult = (GetSubtreeAccessibilityExtendedResult)
           sourceConnection.processExtendedOperation(
                new GetSubtreeAccessibilityExtendedRequest(controls));
      if (sourceResult.getResultCode() != ResultCode.SUCCESS)
      {
        throw new LDAPException(sourceResult);
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new MoveSubtreeResult(le.getResultCode(),
           ERR_MOVE_SUBTREE_CANNOT_GET_ACCESSIBILITY_STATE.get(baseDN,
                INFO_MOVE_SUBTREE_CONNECTION_NAME_SOURCE.get(),
                le.getMessage()),
           null, false, false, 0, 0, 0);
    }

    boolean sourceMatch = false;
    String sourceMessage = null;
    SubtreeAccessibilityRestriction sourceRestriction = null;
    final List<SubtreeAccessibilityRestriction> sourceRestrictions =
         sourceResult.getAccessibilityRestrictions();
    if (sourceRestrictions != null)
    {
      for (final SubtreeAccessibilityRestriction r : sourceRestrictions)
      {
        if (r.getAccessibilityState() == SubtreeAccessibilityState.ACCESSIBLE)
        {
          continue;
        }

        final DN restrictionDN;
        try
        {
          restrictionDN = new DN(r.getSubtreeBaseDN());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new MoveSubtreeResult(ResultCode.INVALID_DN_SYNTAX,
               ERR_MOVE_SUBTREE_CANNOT_PARSE_RESTRICTION_BASE_DN.get(
                    r.getSubtreeBaseDN(),
                    INFO_MOVE_SUBTREE_CONNECTION_NAME_SOURCE.get(),
                    r.toString(), StaticUtils.getExceptionMessage(e)),
               null, false, false, 0, 0, 0);
        }

        if (restrictionDN.equals(parsedBaseDN))
        {
          sourceMatch = true;
          sourceRestriction = r;
          sourceMessage = ERR_MOVE_SUBTREE_NOT_ACCESSIBLE.get(baseDN,
               INFO_MOVE_SUBTREE_CONNECTION_NAME_SOURCE.get(),
               r.getAccessibilityState().getStateName());
          break;
        }
        else if (restrictionDN.isAncestorOf(parsedBaseDN, false))
        {
          sourceRestriction = r;
          sourceMessage = ERR_MOVE_SUBTREE_WITHIN_UNACCESSIBLE_TREE.get(baseDN,
               INFO_MOVE_SUBTREE_CONNECTION_NAME_SOURCE.get(),
               r.getSubtreeBaseDN(), r.getAccessibilityState().getStateName());
          break;
        }
        else if (restrictionDN.isDescendantOf(parsedBaseDN, false))
        {
          sourceRestriction = r;
          sourceMessage = ERR_MOVE_SUBTREE_CONTAINS_UNACCESSIBLE_TREE.get(
               baseDN, INFO_MOVE_SUBTREE_CONNECTION_NAME_SOURCE.get(),
               r.getSubtreeBaseDN(), r.getAccessibilityState().getStateName());
          break;
        }
      }
    }


    // Get the restrictions from the target server.  If there are any, then
    // make sure that nothing in the hierarchy of the base DN is non-accessible.
    final GetSubtreeAccessibilityExtendedResult targetResult;
    try
    {
      targetResult = (GetSubtreeAccessibilityExtendedResult)
           targetConnection.processExtendedOperation(
                new GetSubtreeAccessibilityExtendedRequest(controls));
      if (targetResult.getResultCode() != ResultCode.SUCCESS)
      {
        throw new LDAPException(targetResult);
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new MoveSubtreeResult(le.getResultCode(),
           ERR_MOVE_SUBTREE_CANNOT_GET_ACCESSIBILITY_STATE.get(baseDN,
                INFO_MOVE_SUBTREE_CONNECTION_NAME_TARGET.get(),
                le.getMessage()),
           null, false, false, 0, 0, 0);
    }

    boolean targetMatch = false;
    String targetMessage = null;
    SubtreeAccessibilityRestriction targetRestriction = null;
    final List<SubtreeAccessibilityRestriction> targetRestrictions =
         targetResult.getAccessibilityRestrictions();
    if (targetRestrictions != null)
    {
      for (final SubtreeAccessibilityRestriction r : targetRestrictions)
      {
        if (r.getAccessibilityState() == SubtreeAccessibilityState.ACCESSIBLE)
        {
          continue;
        }

        final DN restrictionDN;
        try
        {
          restrictionDN = new DN(r.getSubtreeBaseDN());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return new MoveSubtreeResult(ResultCode.INVALID_DN_SYNTAX,
               ERR_MOVE_SUBTREE_CANNOT_PARSE_RESTRICTION_BASE_DN.get(
                    r.getSubtreeBaseDN(),
                    INFO_MOVE_SUBTREE_CONNECTION_NAME_TARGET.get(),
                    r.toString(), StaticUtils.getExceptionMessage(e)),
               null, false, false, 0, 0, 0);
        }

        if (restrictionDN.equals(parsedBaseDN))
        {
          targetMatch = true;
          targetRestriction = r;
          targetMessage = ERR_MOVE_SUBTREE_NOT_ACCESSIBLE.get(baseDN,
               INFO_MOVE_SUBTREE_CONNECTION_NAME_TARGET.get(),
               r.getAccessibilityState().getStateName());
          break;
        }
        else if (restrictionDN.isAncestorOf(parsedBaseDN, false))
        {
          targetRestriction = r;
          targetMessage = ERR_MOVE_SUBTREE_WITHIN_UNACCESSIBLE_TREE.get(baseDN,
               INFO_MOVE_SUBTREE_CONNECTION_NAME_TARGET.get(),
               r.getSubtreeBaseDN(), r.getAccessibilityState().getStateName());
          break;
        }
        else if (restrictionDN.isDescendantOf(parsedBaseDN, false))
        {
          targetRestriction = r;
          targetMessage = ERR_MOVE_SUBTREE_CONTAINS_UNACCESSIBLE_TREE.get(
               baseDN, INFO_MOVE_SUBTREE_CONNECTION_NAME_TARGET.get(),
               r.getSubtreeBaseDN(), r.getAccessibilityState().getStateName());
          break;
        }
      }
    }


    // If both the source and target servers are available, then we don't need
    // to do anything else.
    if ((sourceRestriction == null) && (targetRestriction == null))
    {
      return null;
    }


    // If we got a match for both the source and target subtrees, then there's a
    // good chance that condition results from an interrupted earlier attempt at
    // running move-subtree.  If that's the case, then see if we can provide
    // specific advice about how to recover.
    if (sourceMatch || targetMatch)
    {
      // If the source is read-only and the target is hidden, then it was
      // probably in the process of adding entries to the target.  Recommend
      // deleting all entries in the target subtree and making both subtrees
      // accessible before running again.
      if ((sourceRestriction != null) &&
          sourceRestriction.getAccessibilityState().isReadOnly() &&
          (targetRestriction != null) &&
          targetRestriction.getAccessibilityState().isHidden())
      {
        return new MoveSubtreeResult(ResultCode.UNWILLING_TO_PERFORM,
             ERR_MOVE_SUBTREE_POSSIBLY_INTERRUPTED_IN_ADDS.get(baseDN,
                  sourceConnection.getConnectedAddress(),
                  sourceConnection.getConnectedPort(),
                  targetConnection.getConnectedAddress(),
                  targetConnection.getConnectedPort()),
             ERR_MOVE_SUBTREE_POSSIBLY_INTERRUPTED_IN_ADDS_ADMIN_MSG.get(),
             false, false, 0, 0, 0);
      }


      // If the source is hidden and the target is accessible, then it was
      // probably in the process of deleting entries from the source.  Recommend
      // deleting all entries in the source subtree and making the source
      // subtree accessible.  There shouldn't be a need to run again.
      if ((sourceRestriction != null) &&
          sourceRestriction.getAccessibilityState().isHidden() &&
          (targetRestriction == null))
      {
        return new MoveSubtreeResult(ResultCode.UNWILLING_TO_PERFORM,
             ERR_MOVE_SUBTREE_POSSIBLY_INTERRUPTED_IN_DELETES.get(baseDN,
                  sourceConnection.getConnectedAddress(),
                  sourceConnection.getConnectedPort(),
                  targetConnection.getConnectedAddress(),
                  targetConnection.getConnectedPort()),
             ERR_MOVE_SUBTREE_POSSIBLY_INTERRUPTED_IN_DELETES_ADMIN_MSG.get(),
             false, false, 0, 0, 0);
      }
    }


    // If we've made it here, then we're in a situation we don't recognize.
    // Provide general information about the current state of the subtree and
    // recommend that the user contact support if they need assistance.
    final StringBuilder details = new StringBuilder();
    if (sourceMessage != null)
    {
      details.append(sourceMessage);
    }
    if (targetMessage != null)
    {
      append(targetMessage, details);
    }
    return new MoveSubtreeResult(ResultCode.UNWILLING_TO_PERFORM,
         ERR_MOVE_SUBTREE_POSSIBLY_INTERRUPTED.get(baseDN,
              sourceConnection.getConnectedAddress(),
              sourceConnection.getConnectedPort(),
              targetConnection.getConnectedAddress(),
              targetConnection.getConnectedPort(), details.toString()),
         null, false, false, 0, 0, 0);
  }



  /**
   * Updates subtree accessibility in a server.
   *
   * @param  connection        The connection to the server in which the
   *                           accessibility state should be applied.
   * @param  isSource          Indicates whether the connection is to the source
   *                           or target server.
   * @param  baseDN            The base DN for the subtree to move.
   * @param  state             The accessibility state to apply.
   * @param  bypassDN          The DN of a user that will be allowed to bypass
   *                           accessibility restrictions.  It may be
   *                           {@code null} if none is needed.
   * @param  opPurposeControl  An optional operation purpose request control
   *                           that may be included in the request.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to set
   *                         the accessibility state for the subtree.
   */
  private static void setAccessibility(
               @NotNull final LDAPConnection connection,
               final boolean isSource,
               @NotNull final String baseDN,
               @NotNull final SubtreeAccessibilityState state,
               @Nullable final String bypassDN,
               @Nullable final OperationPurposeRequestControl opPurposeControl)
          throws LDAPException
  {
    final String connectionName =
         isSource
         ? INFO_MOVE_SUBTREE_CONNECTION_NAME_SOURCE.get()
         : INFO_MOVE_SUBTREE_CONNECTION_NAME_TARGET.get();

    final Control[] controls;
    if (opPurposeControl == null)
    {
      controls = StaticUtils.NO_CONTROLS;
    }
    else
    {
      controls = new Control[]
      {
        opPurposeControl
      };
    }

    final SetSubtreeAccessibilityExtendedRequest request;
    switch (state)
    {
      case ACCESSIBLE:
        request = SetSubtreeAccessibilityExtendedRequest.
             createSetAccessibleRequest(baseDN, controls);
        break;
      case READ_ONLY_BIND_ALLOWED:
        request = SetSubtreeAccessibilityExtendedRequest.
             createSetReadOnlyRequest(baseDN, true, bypassDN, controls);
        break;
      case READ_ONLY_BIND_DENIED:
        request = SetSubtreeAccessibilityExtendedRequest.
             createSetReadOnlyRequest(baseDN, false, bypassDN, controls);
        break;
      case HIDDEN:
        request = SetSubtreeAccessibilityExtendedRequest.
             createSetHiddenRequest(baseDN, bypassDN, controls);
        break;
      default:
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_MOVE_SUBTREE_UNSUPPORTED_ACCESSIBILITY_STATE.get(
                  state.getStateName(), baseDN, connectionName));
    }

    LDAPResult result;
    try
    {
      result = connection.processExtendedOperation(request);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      result = le.toLDAPResult();
    }

    if (result.getResultCode() != ResultCode.SUCCESS)
    {
      throw new LDAPException(result.getResultCode(),
           ERR_MOVE_SUBTREE_ERROR_SETTING_ACCESSIBILITY.get(
                state.getStateName(), baseDN, connectionName,
                result.getDiagnosticMessage()));
    }
  }



  /**
   * Sets the interrupt message for the given tool, if one was provided.
   *
   * @param  tool     The tool for which to set the interrupt message.  It may
   *                  be {@code null} if no action should be taken.
   * @param  message  The interrupt message to set.  It may be {@code null} if
   *                  an existing interrupt message should be cleared.
   */
  static void setInterruptMessage(@Nullable final MoveSubtree tool,
                                  @Nullable final String message)
  {
    if (tool != null)
    {
      tool.interruptMessage = message;
    }
  }



  /**
   * Deletes a specified set of entries from the indicated server.
   *
   * @param  connection        The connection to use to communicate with the
   *                           server.
   * @param  isSource          Indicates whether the connection is to the source
   *                           or target server.
   * @param  entryDNs          The set of DNs of the entries to be deleted.
   * @param  opPurposeControl  An optional operation purpose request control
   *                           that may be included in the requests.
   * @param  suppressRefInt    Indicates whether to include a request control
   *                           causing referential integrity updates to be
   *                           suppressed on the source server.
   * @param  listener          An optional listener that may be invoked during
   *                           the course of moving entries from the source
   *                           server to the target server.
   * @param  deleteCount       A counter to increment for each delete operation
   *                           processed.
   * @param  resultCode        A reference to the result code to use for the
   *                           move subtree operation.
   * @param  errorMsg          A buffer to which any appropriate error messages
   *                           may be appended.
   *
   * @return  {@code true} if the delete was completely successful, or
   *          {@code false} if any errors were encountered.
   */
  private static boolean deleteEntries(
               @NotNull final LDAPConnection connection,
               final boolean isSource,
               @NotNull final TreeSet<DN> entryDNs,
               @Nullable final OperationPurposeRequestControl opPurposeControl,
               final boolean suppressRefInt,
               @Nullable final MoveSubtreeListener listener,
               @NotNull final AtomicInteger deleteCount,
               @NotNull final AtomicReference<ResultCode> resultCode,
               @NotNull final StringBuilder errorMsg)
  {
    final ArrayList<Control> deleteControlList = new ArrayList<>(3);
    deleteControlList.add(new ManageDsaITRequestControl(true));
    if (opPurposeControl != null)
    {
      deleteControlList.add(opPurposeControl);
    }
    if (suppressRefInt)
    {
      deleteControlList.add(
           new SuppressReferentialIntegrityUpdatesRequestControl(false));
    }

    final Control[] deleteControls = new Control[deleteControlList.size()];
    deleteControlList.toArray(deleteControls);

    boolean successful = true;
    for (final DN dn : entryDNs)
    {
      if (isSource && (listener != null))
      {
        try
        {
          listener.doPreDeleteProcessing(dn);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          resultCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
          append(
               ERR_MOVE_SUBTREE_PRE_DELETE_FAILURE.get(dn.toString(),
                    StaticUtils.getExceptionMessage(e)),
               errorMsg);
          successful = false;
          continue;
        }
      }

      LDAPResult deleteResult;
      try
      {
        deleteResult = connection.delete(new DeleteRequest(dn, deleteControls));
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        deleteResult = le.toLDAPResult();
      }

      if (deleteResult.getResultCode() == ResultCode.SUCCESS)
      {
        deleteCount.incrementAndGet();
      }
      else
      {
        resultCode.compareAndSet(null, deleteResult.getResultCode());
        append(
            ERR_MOVE_SUBTREE_DELETE_FAILURE.get(
                dn.toString(),
                deleteResult.getDiagnosticMessage()),
            errorMsg);
        successful = false;
        continue;
      }

      if (isSource && (listener != null))
      {
        try
        {
          listener.doPostDeleteProcessing(dn);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          resultCode.compareAndSet(null, ResultCode.LOCAL_ERROR);
          append(
               ERR_MOVE_SUBTREE_POST_DELETE_FAILURE.get(dn.toString(),
                    StaticUtils.getExceptionMessage(e)),
               errorMsg);
          successful = false;
        }
      }
    }

    return successful;
  }



  /**
   * Appends the provided message to the given buffer.  If the buffer is not
   * empty, then it will insert two spaces before the message.
   *
   * @param  message  The message to be appended to the buffer.
   * @param  buffer   The buffer to which the message should be appended.
   */
  static void append(@Nullable final String message,
                     @NotNull final StringBuilder buffer)
  {
    if (message != null)
    {
      if (buffer.length() > 0)
      {
        buffer.append("  ");
      }

      buffer.append(message);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleUnsolicitedNotification(
                   @NotNull final LDAPConnection connection,
                   @NotNull final ExtendedResult notification)
  {
    wrapOut(0, 79,
         INFO_MOVE_SUBTREE_UNSOLICITED_NOTIFICATION.get(notification.getOID(),
              connection.getConnectionName(), notification.getResultCode(),
              notification.getDiagnosticMessage()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ReadOnlyEntry doPreAddProcessing(@NotNull final ReadOnlyEntry entry)
  {
    // No processing required.
    return entry;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doPostAddProcessing(@NotNull final ReadOnlyEntry entry)
  {
    wrapOut(0, 79, INFO_MOVE_SUBTREE_ADD_SUCCESSFUL.get(entry.getDN()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doPreDeleteProcessing(@NotNull final DN entryDN)
  {
    // No processing required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doPostDeleteProcessing(@NotNull final DN entryDN)
  {
    wrapOut(0, 79, INFO_MOVE_SUBTREE_DELETE_SUCCESSFUL.get(entryDN.toString()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean registerShutdownHook()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void doShutdownHookProcessing(@Nullable final ResultCode resultCode)
  {
    if (resultCode != null)
    {
      // The tool exited normally, so we don't need to do anything.
      return;
    }

    // If there is an interrupt message, then display it.
    wrapErr(0, 79, interruptMessage);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> exampleMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));

    final String[] args =
    {
      "--sourceHostname", "ds1.example.com",
      "--sourcePort", "389",
      "--sourceBindDN", "uid=admin,dc=example,dc=com",
      "--sourceBindPassword", "password",
      "--targetHostname", "ds2.example.com",
      "--targetPort", "389",
      "--targetBindDN", "uid=admin,dc=example,dc=com",
      "--targetBindPassword", "password",
      "--baseDN", "cn=small subtree,dc=example,dc=com",
      "--sizeLimit", "100",
      "--purpose", "Migrate a small subtree from ds1 to ds2"
    };
    exampleMap.put(args, INFO_MOVE_SUBTREE_EXAMPLE_DESCRIPTION.get());

    return exampleMap;
  }
}
