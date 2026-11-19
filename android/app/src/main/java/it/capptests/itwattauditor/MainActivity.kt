package it.capptests.itwattauditor

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class MainActivity : ComponentActivity() {

    private val viewModel: AuditorViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                AuditorScreen(viewModel)
            }
        }
    }
}

@Composable
private fun AuditorScreen(vm: AuditorViewModel) {
    val context = LocalContext.current
    val exporter = ChainExporter(context)
    val capabilities = vm.engine.capabilities()
    val digests = vm.engine.signingCertificateDigests()
    val saveZip = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/zip")
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            context.contentResolver.openOutputStream(uri)?.use {
                exporter.writeZip(vm.records.list(), vm.deviceInfo(), it)
            }
        }.onSuccess { toast(context, "ZIP saved") }
            .onFailure { toast(context, "Unable to save the ZIP: ${it.message}") }
    }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("ITW Att Auditor", style = MaterialTheme.typography.headlineSmall)
            Text(
                "IT-Wallet hardware key attestation fallback test, without Play Integrity",
                style = MaterialTheme.typography.bodyMedium,
            )

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Device", style = MaterialTheme.typography.titleSmall)
                    Text("Android API ${capabilities.sdkInt}, first API level ${capabilities.firstApiLevel}")
                    Text("Hardware key attestation: ${yesNo(capabilities.isHardwareAttestationSupported)}")
                    Text("App attest key: ${yesNo(capabilities.hasAttestKey)}")
                    Text("StrongBox: ${yesNo(capabilities.hasStrongBox)}")
                    Text("App signing certificate SHA-256 (ANDROID_SIGNATURE_DIGESTS):")
                    digests.forEach { digest ->
                        Text(digest, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                    }
                    TextButton(onClick = {
                        copy(context, digests.joinToString(","))
                        toast(context, "Digest copied")
                    }) { Text("Copy digest") }
                }
            }

            OutlinedTextField(
                value = vm.serverUrl,
                onValueChange = vm::updateServerUrl,
                label = { Text("Backend URL") },
                placeholder = { Text("https://your-project.vercel.app") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                if (vm.registration != null) "Registered: the assertions can be tested" else "Not registered",
                style = MaterialTheme.typography.bodySmall,
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = vm::register, enabled = !vm.busy) { Text("1. Register") }
                Button(onClick = vm::assert, enabled = !vm.busy && vm.registration != null) {
                    Text("2. Assert")
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = vm::localAttestation, enabled = !vm.busy) {
                    Text("Local attestation")
                }
                OutlinedButton(onClick = vm::reset, enabled = !vm.busy) { Text("Reset") }
            }

            if (vm.busy) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())

            if (vm.lastTitle.isNotEmpty()) {
                val outcome = when (vm.lastOutcome) {
                    true -> "OK"
                    false -> "KO"
                    null -> "…"
                }
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = when (vm.lastOutcome) {
                            true -> MaterialTheme.colorScheme.primaryContainer
                            false -> MaterialTheme.colorScheme.errorContainer
                            null -> MaterialTheme.colorScheme.surfaceVariant
                        }
                    ),
                ) {
                    Column(Modifier.padding(12.dp)) {
                        Text("${vm.lastTitle}: $outcome", style = MaterialTheme.typography.titleSmall)
                        SelectionContainer {
                            Text(vm.lastOutput, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                        }
                    }
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Attestation chains (${vm.recordCount} steps)", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "The ZIP stays on the device until you share or save it.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = {
                                context.startActivity(exporter.shareIntent(vm.records.list(), vm.deviceInfo()))
                            },
                            enabled = vm.recordCount > 0,
                        ) { Text("Share ZIP") }
                        OutlinedButton(
                            onClick = { saveZip.launch(ChainExporter.fileName()) },
                            enabled = vm.recordCount > 0,
                        ) { Text("Save ZIP…") }
                    }
                }
            }
        }
    }
}

private fun yesNo(value: Boolean) = if (value) "yes" else "no"

private fun toast(context: Context, text: String) =
    Toast.makeText(context, text, Toast.LENGTH_SHORT).show()

private fun copy(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText("digest", text))
}
