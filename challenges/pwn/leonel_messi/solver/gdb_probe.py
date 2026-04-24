"""GDB script — dumps session offsets we need for the exploit."""
import gdb


def log(msg):
    print(f"[PROBE] {msg}")


class SessionBreak(gdb.Breakpoint):
    def __init__(self, name):
        super().__init__(name, internal=False)
        self.silent = True

    def stop(self):
        # At entry to op_record.
        try:
            libc_base = int(gdb.parse_and_eval("(unsigned long)&__environ")) - 0x222200
            environ_sym = libc_base + 0x222200
            environ_val = int(gdb.parse_and_eval("*(unsigned long*)&__environ"))
            log(f"libc base: {libc_base:#x}")
            log(f"environ sym address: {environ_sym:#x}")
            log(f"environ value (stack ptr to envp array): {environ_val:#x}")

            # Walk up the stack to locate session()'s saved RIP. session is
            # in the current call chain when op_record is called — frame 1.
            frame = gdb.selected_frame()  # op_record
            caller = frame.older()  # session
            if caller is None:
                log("no caller"); return False
            outer = caller.older()  # main (where session was called from)
            if outer is None:
                log("no outer"); return False
            saved_rip_val = int(outer.pc())  # pc of caller (main) = ret target
            # saved_rip is stored at caller_sp - 8 (just above caller frame)
            sp_of_main = int(outer.read_register('rsp'))
            log(f"session saved RIP value: {saved_rip_val:#x}")
            log(f"main's rsp at call site: {sp_of_main:#x}")
            log(f"session->main return addr lives at: {sp_of_main - 8:#x}")
            log(f"session saved RIP = environ_val - {environ_val - (sp_of_main - 8):#x}")

            # Derive binary base
            session_addr = int(caller.pc())
            log(f"current PC inside session/op_record: {session_addr:#x}")
        except Exception as e:
            log(f"error: {e}")
        return False  # don't actually halt


# session is stripped, but op_record was marked noinline + used — it
# should survive as a resolvable symbol via its relative offset in the
# binary. If stripped, fall back to a pattern break.
gdb.execute("set pagination off")
gdb.execute("set print symbol-loading off")
# break at op_record via address resolution will be done interactively
