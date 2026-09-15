// BARE: which functions reference the strings the static pass flagged.
//
// Run by sandbox/images/ghidra/analyzer.py as an analyzeHeadless -postScript,
// after auto-analysis, once per binary. Arguments:
//
//   0  a file of decimal file offsets, one per line, as the static pass
//      recorded them
//   1  where to write the JSON result
//
// The output is one object per offset in the shape core/analyzers/ghidra_result.py
// reads. This script reads the program and never modifies it, and it writes no
// decompiled source: a decompiled use site contains the string literal itself,
// and the string literal is the secret (ADR-0034).
//
//@category BARE

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;

public class BareXrefs extends GhidraScript {

    // Mirrors MAX_REFERENCES_PER_TARGET in ghidra_result.py; the analyzer caps
    // again on the Python side, so this only bounds how much JSON is written.
    private static final int MAX_REFERENCES_PER_TARGET = 32;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: BareXrefs <offsets-file> <output-json>");
        }

        List<Long> offsets = new ArrayList<>();
        for (String line : Files.readAllLines(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                offsets.add(Long.parseLong(trimmed));
            }
        }

        Memory memory = currentProgram.getMemory();
        JsonArray targets = new JsonArray();
        for (long offset : offsets) {
            monitor.checkCancelled();
            targets.add(target(memory, offset));
        }

        JsonObject result = new JsonObject();
        result.addProperty("language", currentProgram.getLanguageID().getIdAsString());
        result.addProperty("function_count", currentProgram.getFunctionManager().getFunctionCount());
        result.add("targets", targets);

        String json = new GsonBuilder().serializeNulls().create().toJson(result);
        Files.write(Paths.get(args[1]), json.getBytes(StandardCharsets.UTF_8));
    }

    private JsonObject target(Memory memory, long offset) {
        JsonObject target = new JsonObject();
        target.addProperty("file_offset", offset);

        // The static pass records a file offset; code refers to a memory
        // address. Translating between them is the loader's knowledge, and an
        // offset with no mapping (an overlay, a resource never loaded) is a
        // real answer rather than an error.
        List<Address> mapped = memory.locateAddressesForFileOffset(offset);
        if (mapped.isEmpty()) {
            target.add("address", JsonNull.INSTANCE);
            target.addProperty("found", false);
            target.add("references", new JsonArray());
            return target;
        }

        Address address = mapped.get(0);
        target.addProperty("address", hex(address));

        // A rule can match inside a longer string ("password=hunter2"), and code
        // references where the string starts, not where the match does.
        Data data = getDataContaining(address);
        Address start = data != null ? data.getMinAddress() : address;

        // Keyed by address so the output order is Ghidra's address order, which
        // is what makes best_function deterministic on the Python side.
        Map<Address, Reference> sites = new TreeMap<>();
        collect(start, sites, true);
        if (!start.equals(address)) {
            collect(address, sites, true);
        }

        JsonArray references = new JsonArray();
        for (Reference reference : sites.values()) {
            if (references.size() >= MAX_REFERENCES_PER_TARGET) {
                break;
            }
            references.add(site(reference));
        }

        target.addProperty("found", data != null || !sites.isEmpty());
        target.add("references", references);
        return target;
    }

    private void collect(Address to, Map<Address, Reference> sites, boolean followPointers) {
        for (Reference reference : getReferencesTo(to)) {
            Address from = reference.getFromAddress();
            if (getFunctionContaining(from) != null || !followPointers) {
                sites.putIfAbsent(from, reference);
                continue;
            }
            // Referenced from data rather than code: usually a pointer slot, as
            // in `static const char *KEY = "..."`. The use is one hop further on,
            // in whatever reads the pointer. One hop only — following chains of
            // data references is how a jump table becomes ten thousand "uses".
            int before = sites.size();
            collect(from, sites, false);
            if (sites.size() == before) {
                sites.putIfAbsent(from, reference);
            }
        }
    }

    private JsonObject site(Reference reference) {
        Address from = reference.getFromAddress();
        Function function = getFunctionContaining(from);

        JsonObject site = new JsonObject();
        site.addProperty("from_address", hex(from));
        site.addProperty("reference_type", reference.getReferenceType().getName());
        site.addProperty("function", function == null ? null : function.getName());
        site.addProperty(
            "function_address", function == null ? null : hex(function.getEntryPoint()));
        site.add("context", JsonNull.INSTANCE);
        return site;
    }

    private static String hex(Address address) {
        return "0x" + Long.toHexString(address.getOffset());
    }
}
