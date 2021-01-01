/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;



/**
 * This class provides test coverage for methods in the {@code LDAPRequest} and
 * {@code UpdatableLDAPRequest} classes.
 */
public class UpdatableLDAPRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the methods used to interact with controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControls()
         throws Exception
  {
    DeleteRequest r = new DeleteRequest("dc=example,dc=com");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getControlList());
    assertTrue(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 0);

    assertFalse(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.addControl(new Control("1.2.3.4"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 1);

    assertTrue(r.hasControl());

    assertTrue(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNotNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.setControls(new Control("1.2.3.4"),
                  new Control("1.2.3.5"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 2);

    assertTrue(r.hasControl());

    assertTrue(r.hasControl("1.2.3.4"));
    assertTrue(r.hasControl("1.2.3.5"));

    assertNotNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));


    assertTrue(r.removeControl(new Control("1.2.3.4")));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 1);

    assertTrue(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertTrue(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));


    assertFalse(r.removeControl(new Control("1.2.3.4")));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 1);

    assertTrue(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertTrue(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));


    r.setControls(Arrays.asList(new Control("1.2.3.4")));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 1);

    assertTrue(r.hasControl());

    assertTrue(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNotNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    assertTrue(r.removeControl(new Control("1.2.3.4")));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getControlList());
    assertTrue(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 0);

    assertFalse(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.setControls();

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getControlList());
    assertTrue(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 0);

    assertFalse(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.addControls(new Control("1.2.3.4"),
                  new Control("1.2.3.5"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 2);

    assertTrue(r.hasControl());

    assertTrue(r.hasControl("1.2.3.4"));
    assertTrue(r.hasControl("1.2.3.5"));

    assertNotNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));


    r.setControls((Control[]) null);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getControlList());
    assertTrue(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 0);

    assertFalse(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.setControls((List<Control>) null);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getControlList());
    assertTrue(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 0);

    assertFalse(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.setControls(new Control("1.2.3.4"),
                  new Control("1.2.3.5"));
    assertNotNull(r.removeControl("1.2.3.5"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 1);

    assertTrue(r.hasControl());

    assertTrue(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNotNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    assertNull(r.removeControl("1.2.3.5"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 1);

    assertTrue(r.hasControl());

    assertTrue(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNotNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    assertNotNull(r.removeControl("1.2.3.4"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getControlList());
    assertTrue(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 0);

    assertFalse(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.setControls(Arrays.<Control>asList());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getControlList());
    assertTrue(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 0);

    assertFalse(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.replaceControl(new Control("1.2.3.4"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 1);

    assertTrue(r.hasControl());

    assertTrue(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNotNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.replaceControl(new Control("1.2.3.4"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 1);

    assertTrue(r.hasControl());

    assertTrue(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNotNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.replaceControl("1.2.3.4", new Control("1.2.3.5"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 1);

    assertTrue(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertTrue(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));


    r.replaceControl("1.2.3.5", new Control("1.2.3.5"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 1);

    assertTrue(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertTrue(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));


    r.replaceControl("1.2.3.4", null);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 1);

    assertTrue(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertTrue(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));


    r.replaceControl("1.2.3.5", null);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getControlList());
    assertTrue(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 0);

    assertFalse(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.replaceControl(new Control("1.2.3.4"));
    r.replaceControl(new Control("1.2.3.5"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 2);

    assertTrue(r.hasControl());

    assertTrue(r.hasControl("1.2.3.4"));
    assertTrue(r.hasControl("1.2.3.5"));

    assertNotNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));


    r.replaceControl("1.2.3.4", null);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 1);

    assertTrue(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertTrue(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));


    r.replaceControl("1.2.3.5", null);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getControlList());
    assertTrue(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 0);

    assertFalse(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.addControls();

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getControlList());
    assertTrue(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 0);

    assertFalse(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.addControls((Control[]) null);

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getControlList());
    assertTrue(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 0);

    assertFalse(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.addControls(new Control("1.2.3.4"),
                  new Control("1.2.3.4"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 2);

    assertTrue(r.hasControl());

    assertTrue(r.hasControl("1.2.3.4"));
    assertFalse(r.hasControl("1.2.3.5"));

    assertNotNull(r.getControl("1.2.3.4"));
    assertNull(r.getControl("1.2.3.5"));


    r.replaceControl("1.2.3.4", new Control("1.2.3.5"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 2);

    assertTrue(r.hasControl());

    assertTrue(r.hasControl("1.2.3.4"));
    assertTrue(r.hasControl("1.2.3.5"));

    assertNotNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));


    r.replaceControl("1.2.3.4", new Control("1.2.3.5"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 2);

    assertTrue(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertTrue(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));


    r.replaceControl("1.2.3.4", new Control("1.2.3.5"));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 3);

    assertNotNull(r.getControlList());
    assertFalse(r.getControlList().isEmpty());
    assertEquals(r.getControlList().size(), 3);

    assertTrue(r.hasControl());

    assertFalse(r.hasControl("1.2.3.4"));
    assertTrue(r.hasControl("1.2.3.5"));

    assertNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));
  }



  /**
   * Tests the methods used to interact with the response timeout.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testResponseTimeout()
         throws Exception
  {
    LDAPConnection c = new LDAPConnection();
    c.getConnectionOptions().setResponseTimeoutMillis(1234L);

    DeleteRequest r = new DeleteRequest("dc=example,dc=com");

    r.setResponseTimeoutMillis(0L);
    assertEquals(r.getResponseTimeoutMillis(c), 0L);

    r.setResponseTimeoutMillis(5678L);
    assertEquals(r.getResponseTimeoutMillis(c), 5678L);

    r.setResponseTimeoutMillis(-1L);
    assertEquals(r.getResponseTimeoutMillis(c), 1234L);

    c.getConnectionOptions().setResponseTimeoutMillis(4321L);
    r.setResponseTimeoutMillis(-5678L);
    assertEquals(r.getResponseTimeoutMillis(c), 4321L);
  }
}
