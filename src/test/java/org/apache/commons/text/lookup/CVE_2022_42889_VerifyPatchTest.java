/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache license, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the license for the specific language governing permissions and
 * limitations under the license.
 */
package org.apache.commons.text.lookup;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Verifies the patch for CVE-2022-42889 (Text4Shell).
 *
 * The exploit vector: ${script:javascript:java.lang.Runtime.getRuntime().exec('calc')}
 * If the patch is active, the script/url/dns lookups are absent from the default
 * interpolator and the malicious payload is returned unchanged (not executed).
 */
public class CVE_2022_42889_VerifyPatchTest {


    @Test
    public void scriptLookupNotInDefaults() {
        final Map<String, StringLookup> defaults = new HashMap<>();
        StringLookupFactory.INSTANCE.addDefaultStringLookups(defaults);

        assertFalse(defaults.containsKey("script"),
                "PATCH FAILED: 'script' lookup is present in defaults — CVE-2022-42889 RCE possible");
        System.out.println("[CVE-2022-42889] PASS: 'script' lookup absent from defaults");
    }

    @Test
    public void urlLookupNotInDefaults() {
        final Map<String, StringLookup> defaults = new HashMap<>();
        StringLookupFactory.INSTANCE.addDefaultStringLookups(defaults);

        assertFalse(defaults.containsKey("url"),
                "PATCH FAILED: 'url' lookup is present in defaults — CVE-2022-42889 SSRF possible");
        assertFalse(defaults.containsKey("urlDecoder"),
                "PATCH FAILED: 'urlDecoder' lookup is present in defaults — CVE-2022-42889");
        assertFalse(defaults.containsKey("urlEncoder"),
                "PATCH FAILED: 'urlEncoder' lookup is present in defaults — CVE-2022-42889");
        System.out.println("[CVE-2022-42889] PASS: 'url' family absent from defaults");
    }

    @Test
    public void dnsLookupNotInDefaults() {
        final Map<String, StringLookup> defaults = new HashMap<>();
        StringLookupFactory.INSTANCE.addDefaultStringLookups(defaults);

        assertFalse(defaults.containsKey("dns"),
                "PATCH FAILED: 'dns' lookup is present in defaults — CVE-2022-42889 SSRF possible");
        System.out.println("[CVE-2022-42889] PASS: 'dns' key absent from defaults");
    }

    @Test
    public void rcePayloadNotExecutedByDefaultInterpolator() {
        // On a vulnerable system this would exec calc; on a patched system the lookup returns null.
        final InterpolatorStringLookup lookup = new InterpolatorStringLookup();
        final String result = lookup.lookup("script:javascript:java.lang.Runtime.getRuntime().exec('calc')");
        assertNull(result,
                "PATCH FAILED: script lookup resolved — RCE gadget would execute on a patched build");
        System.out.println("[CVE-2022-42889] PASS: RCE payload returned null (not executed). result=" + result);
    }

    @Test
    public void ssrfUrlPayloadNotExecutedByDefaultInterpolator() {
        final InterpolatorStringLookup lookup = new InterpolatorStringLookup();
        final String result = lookup.lookup("url:UTF-8:http://169.254.169.254/latest/meta-data/");
        assertNull(result,
                "PATCH FAILED: url lookup resolved — SSRF gadget active on a patched build");
        System.out.println("[CVE-2022-42889] PASS: SSRF/URL payload returned null. result=" + result);
    }
}
