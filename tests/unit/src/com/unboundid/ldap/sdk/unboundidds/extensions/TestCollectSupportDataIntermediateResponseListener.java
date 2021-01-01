/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.util.ByteStringBuffer;



/**
 * This class provides an implementation of a collect support data intermediate
 * response listener that will capture the intermediate response messages
 * provided to it.
 */
public final class TestCollectSupportDataIntermediateResponseListener
       implements CollectSupportDataIntermediateResponseListener
{
  // The buffer to which the archive fragments will be appended.
  private final ByteStringBuffer archiveData;

  // The list of other intermediate responses.
  private final List<IntermediateResponse> otherResponses;

  // The list of messages written to standard error.
  private final List<String> standardErrorMessages;

  // The list of messages written to standard output.
  private final List<String> standardOutputMessages;



  /**
   * Creates a new instance of this intermediate response listener.
   */
  public TestCollectSupportDataIntermediateResponseListener()
  {
    standardOutputMessages = new ArrayList<>(10);
    standardErrorMessages = new ArrayList<>(10);
    archiveData = new ByteStringBuffer();
    otherResponses = new ArrayList<>(10);
  }



  /**
   * Retrieves a list of messages written to standard output.
   *
   * @return  A list of messages written to standard output.
   */
  public List<String> getStandardOutputMessages()
  {
    return Collections.unmodifiableList(
         new ArrayList<>(standardOutputMessages));
  }



  /**
   * Retrieves a list of messages written to standard error.
   *
   * @return  A list of messages written to standard error.
   */
  public List<String> getStandardErrorMessages()
  {
    return Collections.unmodifiableList(
         new ArrayList<>(standardErrorMessages));
  }



  /**
   * Retrieves the support data archive that has been written so far.
   *
   * @return  The support data archive that has been written so far.
   */
  public byte[] getArchiveData()
  {
    return archiveData.toByteArray();
  }



  /**
   * Retrieves a list of the other intermediate responses returned to the
   * client.
   *
   * @return  A list of the other intermediate responses returned to the
   *          client.
   */
  public List<IntermediateResponse> getOtherResponses()
  {
    return Collections.unmodifiableList(new ArrayList<>(otherResponses));
  }



  /**
   * Resets this listener to clear all lists and buffers.
   */
  public void clear()
  {
    standardOutputMessages.clear();
    standardErrorMessages.clear();
    archiveData.clear();
    otherResponses.clear();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleOutputIntermediateResponse(
       final CollectSupportDataOutputIntermediateResponse response)
  {
    switch (response.getOutputStream())
    {
      case STANDARD_OUTPUT:
        standardOutputMessages.add(response.getOutputMessage());
        break;
      case STANDARD_ERROR:
        standardErrorMessages.add(response.getOutputMessage());
        break;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleArchiveFragmentIntermediateResponse(
       final CollectSupportDataArchiveFragmentIntermediateResponse response)
  {
    archiveData.append(response.getFragmentData());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleOtherIntermediateResponse(
       final IntermediateResponse response)
  {
    otherResponses.add(response);
  }
}
