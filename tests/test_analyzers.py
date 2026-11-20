"""Check rule variants with small synthetic snippets read only as text."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import scan
from analyzers.common import Kotlin, submission_report
from analyzers.sast import kotlin_sast
from analyzers.secrets import kotlin_secrets


class AnalyzerTests(unittest.TestCase):
    def test_secret_roles_and_safe_references(self):
        doc = Kotlin("Connector.kt", '''
            const val tokenEndpoint = "https://example.invalid"
            val internalApiKey = "fixture-value-for-a-test"
            val ignoredPassword = System.getenv("STAGING_PASSWORD")
            /* outer /* nested */ val servicePassword = "comment-only" */
            fun headers() {
                val prefix = "synthetic-"
                val suffix = "fragment"
                val credential = prefix + suffix
                headers.setBearerAuth(credential)
            }
        ''')
        found = list(kotlin_secrets(doc))
        self.assertEqual([(item["rule"], item["line"]) for item in found], [("api-key", 3), ("recoverable-token", 7)])
        self.assertNotIn("fixture-value-for-a-test", json.dumps(found))

    def test_cors_wildcard_requires_same_configuration(self):
        broad = 'val a = CorsConfiguration().apply { allowedOrigins = listOf("https://example.invalid", "*"); allowCredentials = true }'
        split = 'val a = CorsConfiguration().apply { allowedOrigins = listOf("*") }; val b = CorsConfiguration().apply { allowCredentials = true }'
        for statements, expected in [(broad, ["credentialed-cors"]), (split, [])]:
            doc = Kotlin("Options.kt", f"fun options() {{ {statements} }}")
            self.assertEqual([item["rule"] for item in kotlin_sast([doc])], expected)

    def test_sql_query_and_bound_control(self):
        doc = Kotlin("Inventory.kt", '''
            import org.springframework.jdbc.core.JdbcTemplate
            fun lookup(@RequestParam serial: String) =
                jdbc.queryForList("SELECT name FROM inventory WHERE serial = '$serial'")
            fun bound(@RequestParam serial: String) =
                jdbc.queryForList("SELECT name FROM inventory WHERE serial = ?", serial)
        ''')
        self.assertEqual([(item["rule"], item["line"]) for item in kotlin_sast([doc])], [("sql-injection", 3)])

    def test_object_check_follows_renamed_receiver_and_owner_predicate(self):
        controller = Kotlin("Endpoint.kt", '''
            @RestController class Endpoint(private val assets: AssetStore) {
                fun get(@PathVariable ref: Long) = assets.fetch(ref)
            }
        ''')
        reader = '''
            class AssetStore(private val db: JdbcTemplate) {
                fun fetch(ref: Long) = db.query("SELECT title, owner_id FROM assets WHERE asset_id = ?%s", ref)
            }
        '''
        for predicate, expected in [("", ["object-authorization"]), (" AND owner_id = ?", [])]:
            doc = Kotlin("Assets.kt", reader % predicate)
            self.assertEqual([item["rule"] for item in kotlin_sast([controller, doc])], expected)

    def test_sca_resolves_properties_locks_and_inclusive_bounds(self):
        runtime = Path(__file__).resolve().parents[1] / ".runtime"
        runtime.mkdir(exist_ok=True)
        with TemporaryDirectory(dir=runtime) as folder:
            project = Path(folder)
            (project / "gradle.properties").write_text("fixtureVersion=1.5\n", encoding="utf-8")
            (project / "gradle.lockfile").write_text("sample:lock:2.1=runtimeClasspath\n", encoding="utf-8")
            (project / "build.gradle.kts").write_text('''val fixture = providers.gradleProperty("fixtureVersion").get()
                dependencies {
                    add("implementation", "sample:property:$fixture", )
                    implementation(version = "1.0", name = "lock", group = "sample")
                    implementation("sample:fixed:1.6")
                    implementation("sample:dynamic:1.5" + otherVersion)
                    // implementation("sample:comment:1.0")
                }
                fun fixture() = implementation("sample:outside:1.0")
            ''', encoding="utf-8")
            advisories = [{
                "id": "GHSA-aaaa-bbbb-cccc", "group": "sample", "artifact": name, "severity": "MEDIUM",
                "ranges": [{"lower": "1.0", "lowerInclusive": True, "upper": "1.5.0", "upperInclusive": True}],
            } for name in ("property", "lock", "fixed", "dynamic", "comment", "outside")]
            advisory_path = project / "catalog.json"
            advisory_path.write_text(json.dumps({"vulnerabilities": advisories}), encoding="utf-8")
            result = scan.scan(project, scan.load_catalog(advisory_path), scanners={"sca"})
            self.assertEqual(result["sca"]["unresolved_versions"], [])
            self.assertEqual([(item["package"], item["line"]) for item in result["findings"]], [("sample:property", 3)])
            self.assertEqual(submission_report(result)["findings"][0]["advisoryId"], "GHSA-aaaa-bbbb-cccc")


if __name__ == "__main__":
    unittest.main()
