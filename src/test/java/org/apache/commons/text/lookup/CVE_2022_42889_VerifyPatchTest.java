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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.text.StringSubstitutor;
import org.junit.jupiter.api.Test;

/**
 * Verifies the backport of the CVE-2022-42889 (Text4Shell) fix.
 * <p>
 * Exploit shape: when untrusted input reaches {@link StringSubstitutor#createInterpolator()}, the
 * {@code ${script:...}}, {@code ${dns:...}}, and {@code ${url:...}} prefixes let an attacker run arbitrary
 * JVM script engine code, trigger DNS lookups, or fetch remote URLs. A patched build must not register
 * those three lookups as defaults, so the payloads below must come back unresolved.
 * </p>
 */
public class CVE_2022_42889_VerifyPatchTest {

    @Test
    public void scriptDnsAndUrlAreNotInDefaultLookups() {
        final Map<String, StringLookup> defaults = new HashMap<>();
        StringLookupFactory.INSTANCE.addDefaultStringLookups(defaults);

        assertFalse(defaults.containsKey(InterpolatorStringLookup.toKey(StringLookupFactory.KEY_SCRIPT)),
                "PATCH FAILED: 'script' lookup is present in defaults - CVE-2022-42889 RCE possible");
        assertFalse(defaults.containsKey(InterpolatorStringLookup.toKey(StringLookupFactory.KEY_DNS)),
                "PATCH FAILED: 'dns' lookup is present in defaults - CVE-2022-42889 SSRF possible");
        assertFalse(defaults.containsKey(InterpolatorStringLookup.toKey(StringLookupFactory.KEY_URL)),
                "PATCH FAILED: 'url' lookup is present in defaults - CVE-2022-42889 SSRF possible");
    }

    @Test
    public void rceScriptPayloadIsNotExecutedByDefaultInterpolator() {
        // Benign arithmetic stands in for the RCE payload (e.g. Runtime.exec via Nashorn) so the test
        // doesn't spawn a process; what matters is whether the script engine runs at all by default.
        final String payload = "${script:javascript:3 + 4}";
        final String result = StringSubstitutor.createInterpolator().replace(payload);
        assertEquals(payload, result,
                "PATCH FAILED: script payload resolved - RCE gadget would run on a patched build");
    }

    @Test
    public void ssrfUrlPayloadIsNotFetchedByDefaultInterpolator() {
        // A local file:// target stands in for a remote SSRF target so the test has no network dependency;
        // what matters is whether the url lookup fetches anything at all by default.
        final String payload = "${url:UTF-8:file:///" + new java.io.File("pom.xml").getAbsolutePath() + "}";
        final String result = StringSubstitutor.createInterpolator().replace(payload);
        assertEquals(payload, result,
                "PATCH FAILED: url payload resolved - SSRF/LFI gadget is active on a patched build");
    }

    @Test
    public void dnsPayloadIsNotResolvedByDefaultInterpolator() {
        final String payload = "${dns:address|localhost}";
        final String result = StringSubstitutor.createInterpolator().replace(payload);
        assertEquals(payload, result,
                "PATCH FAILED: dns payload resolved - SSRF/exfiltration gadget is active on a patched build");
    }

    /**
     * Confirms the fix's scope: urlDecoder/urlEncoder (no remote/code-execution capability) remain
     * available by default, matching the upstream fix in commit b9b40b903e2d1f9935039803c9852439576780ea.
     */
    @Test
    public void urlEncoderAndDecoderRemainAvailableByDefault() {
        final StringSubstitutor interpolator = StringSubstitutor.createInterpolator();
        assertEquals("Hello World!", interpolator.replace("${urlDecoder:Hello%20World%21}"));
        assertEquals("Hello+World%21", interpolator.replace("${urlEncoder:Hello World!}"));
    }
}
