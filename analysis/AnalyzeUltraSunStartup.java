import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class AnalyzeUltraSunStartup extends GhidraScript {
	private static final long[] TARGETS = {
		0x00100024L, 0x001045B4L, 0x0010693CL, 0x00104628L,
		0x00100EF0L, 0x00104580L, 0x00104608L, 0x00104500L,
		0x001044F8L
	};
	private static final String[] LABELS = {
		"zero_region", "startup_call_1", "startup_call_2", "startup_call_3",
		"startup_call_4_thumb", "initializer_table", "startup_call_6",
		"main_dispatch_candidate", "exit_stub_candidate"
	};

	@Override
	public void run() throws Exception {
		for (int index = 0; index < TARGETS.length; index++) {
			Address entry = toAddr(TARGETS[index]);
			Address end = entry.add(0x100);
			DisassembleCommand command = new DisassembleCommand(entry,
				new AddressSet(entry, end), false);
			if (!command.applyTo(currentProgram, monitor)) {
				println("DISASSEMBLY_WARNING " + entry + " " + command.getStatusMsg());
			}
			Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
			if (function == null) {
				function = createFunction(entry, LABELS[index]);
			}
			println("STARTUP_TARGET " + entry + " label=" + LABELS[index] +
				" function=" + (function != null) +
				" bytes=" + (function == null ? 0 : function.getBody().getNumAddresses()));
			if (function != null) {
				InstructionIterator instructions = currentProgram.getListing()
					.getInstructions(function.getBody(), true);
				int emitted = 0;
				while (instructions.hasNext() && emitted < 40) {
					Instruction instruction = instructions.next();
					println("  INSN " + instruction.getAddress() + " " + instruction);
					emitted++;
				}
			}
		}
	}
}

