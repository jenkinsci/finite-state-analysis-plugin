package io.jenkins.plugins.finitestate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/** Unit coverage for the pure helpers in {@link FiniteStateApiClient}. */
public class FiniteStateApiClientTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void escapeRsqlEscapesQuotesBackslashesAndWildcards() {
        assertEquals("a\\\"b", FiniteStateApiClient.escapeRsql("a\"b"));
        assertEquals("a\\\\b", FiniteStateApiClient.escapeRsql("a\\b"));
        assertEquals("a\\*b", FiniteStateApiClient.escapeRsql("a*b"));
        assertEquals("plain name", FiniteStateApiClient.escapeRsql("plain name"));
    }

    @Test
    public void buildUiUrlMatchesAdoPattern() {
        assertEquals(
                "https://fs-foo.finitestate.io/projects/p1/versions/v1/bill-of-materials?view=list",
                FiniteStateApiClient.buildUiUrl("fs-foo.finitestate.io", "p1", "v1"));
    }

    @Test
    public void terminalStatusClassification() {
        assertTrue(FiniteStateApiClient.isSuccessTerminal("COMPLETED"));
        assertTrue(FiniteStateApiClient.isSuccessTerminal("COMPLETED_WITH_WARNINGS"));
        assertTrue(FiniteStateApiClient.isFailureTerminal("ERROR"));
        assertTrue(FiniteStateApiClient.isFailureTerminal("CANCELLED"));
        assertFalse(FiniteStateApiClient.isTerminal("STARTED"));
        assertFalse(FiniteStateApiClient.isTerminal("PROCESSING"));
        assertTrue(FiniteStateApiClient.isTerminal("COMPLETED"));
    }

    @Test
    public void detectSbomFormatByExtension() throws Exception {
        File cdx = tmp.newFile("sbom.cdx.json");
        Files.writeString(cdx.toPath(), "{\"bomFormat\":\"CycloneDX\"}", StandardCharsets.UTF_8);
        assertEquals("cyclonedx", FiniteStateApiClient.detectSbomFormat(cdx));

        File spdxByName = tmp.newFile("sbom.spdx.json");
        Files.writeString(spdxByName.toPath(), "{}", StandardCharsets.UTF_8);
        assertEquals("spdx", FiniteStateApiClient.detectSbomFormat(spdxByName));
    }

    @Test
    public void detectSbomFormatByContent() throws Exception {
        File spdxByContent = tmp.newFile("bom.json");
        Files.writeString(
                spdxByContent.toPath(),
                "{\"spdxVersion\":\"SPDX-2.3\",\"SPDXID\":\"SPDXRef-DOCUMENT\"}",
                StandardCharsets.UTF_8);
        assertEquals("spdx", FiniteStateApiClient.detectSbomFormat(spdxByContent));

        File cdxByContent = tmp.newFile("bom2.json");
        Files.writeString(
                cdxByContent.toPath(), "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\"}", StandardCharsets.UTF_8);
        assertEquals("cyclonedx", FiniteStateApiClient.detectSbomFormat(cdxByContent));
    }
}
