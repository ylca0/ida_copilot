"""IDA tools exposed to the Pydantic AI agent.

Every function in :data:`IDA_TOOLS` is an ``async`` function whose first
parameter is ``ctx: RunContext`` (the agent passes its deps through it). Each
returns JSON-serializable data so the model can reason over the results.

IDA APIs may only be called from IDA's main thread. Since the agent runs on a
background worker thread, every tool is decorated with :func:`ida_tool`, which
re-dispatches the whole body to the main thread via ``execute_sync``.
"""

from __future__ import annotations

import functools
import re
from typing import Any, Awaitable, Callable

from pydantic_ai import RunContext

_DEPS_KEY = "ida"

# ---------------------------------------------------------------------------
# Lazy IDA helpers
# ---------------------------------------------------------------------------

_IDA_IMPORTS: dict[str, Any] = {}


def _ida() -> dict[str, Any]:
    """Import the IDA modules once and return the mapping used by the tools."""
    if _IDA_IMPORTS:
        return _IDA_IMPORTS
    try:
        import ida_auto
        import ida_bytes
        import ida_funcs
        import ida_hexrays
        import ida_idaapi
        import ida_kernwin
        import ida_lines
        import ida_nalt
        import ida_name
        import ida_segment
        import ida_typeinf
        import ida_ua
        import ida_xref
        import idautils
    except ImportError as e:  # outside IDA (e.g. tests)
        raise RuntimeError(f"IDA modules are not available in this Python: {e}") from e
    _IDA_IMPORTS.update(
        auto=ida_auto,
        bytes=ida_bytes,
        funcs=ida_funcs,
        hexrays=ida_hexrays,
        idaapi=ida_idaapi,
        kernwin=ida_kernwin,
        lines=ida_lines,
        nalt=ida_nalt,
        name=ida_name,
        segment=ida_segment,
        typeinf=ida_typeinf,
        ua=ida_ua,
        xref=ida_xref,
        autils=idautils,
    )
    return _IDA_IMPORTS


def _run_on_main(sync_fn: Callable[[], Any], write: bool = False) -> Any:
    """Run ``sync_fn`` on IDA's main thread and return its result.

    Uses ``execute_sync`` which, when called from a background thread, queues
    the callable on the main thread and blocks until it finishes. When already
    on the main thread it runs inline. If IDA is unavailable (e.g. running
    outside IDA for tests) the callable runs directly.
    """
    try:
        import ida_kernwin
    except ImportError:
        return sync_fn()

    box: dict[str, Any] = {}

    def runner() -> int:
        try:
            box["value"] = sync_fn()
        except BaseException as e:  # noqa: BLE001 - propagate any error
            box["error"] = e
        return 0

    ida_kernwin.execute_sync(
        runner,
        ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ,
    )
    if "error" in box:
        raise box["error"]
    return box.get("value")


def ida_tool(write: bool = False):
    """Decorator: re-dispatch an async tool body to IDA's main thread.

    The tool functions in this module never ``await`` anything; they only make
    synchronous IDA calls. We therefore drive the coroutine to completion inside
    ``execute_sync`` on the main thread.
    """

    def deco(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @functools.wraps(fn)
        async def wrapper(ctx: RunContext, *args: Any, **kwargs: Any) -> Any:
            coro = fn(ctx, *args, **kwargs)

            def body() -> Any:
                try:
                    coro.send(None)
                    # If the function ever awaits (it shouldn't), keep pumping:
                    while True:
                        try:
                            coro.send(None)
                        except StopIteration as stop:
                            return stop.value
                except StopIteration as stop:
                    return stop.value

            result = _run_on_main(body, write=write)
            # Strip IDA colour/control tags from any text returned to the model,
            # so control bytes never render as garbage glyphs in the UI.
            if isinstance(result, str):
                return _strip_control_chars(result)
            return result

        return wrapper

    return deco


def _ea_of(name_or_ea: str) -> int:
    """Resolve a hex string, decimal string, or symbol name to an ea_t."""
    s = str(name_or_ea).strip()
    if not s:
        return 0
    try:
        return int(s, 16) if s.lower().startswith(("0x", "0x")) else int(s)
    except ValueError:
        pass
    ida = _ida()
    bad = ida["idaapi"].BADADDR
    return ida["name"].get_name_ea(bad, s)


def _fmt_ea(ea: int) -> str:
    return "0x%X" % ea


# IDA colour-tag control characters. Lines coming from disassembly/pseudocode
# are wrapped in these tags (e.g. \x01 ... \x02); without stripping them the
# raw control bytes render as garbage glyphs ("" etc.) in HTML.
# Keep \t, \r, \n (whitespace) intact.
_COLOR_TAG_CHARS = frozenset(range(0x01, 0x20)) - {ord("\t"), ord("\r"), ord("\n")}


def _strip_control_chars(text: str) -> str:
    """Remove control characters that are not tabs/newlines."""
    return "".join(ch for ch in text if ord(ch) not in _COLOR_TAG_CHARS)



def _disasm_range(start: int, end: int, max_lines: int = 400) -> list[str]:
    """Disassemble [start, end) into a list of textual lines."""
    ida = _ida()
    lines: list[str] = []
    ea = start
    while ea < end and len(lines) < max_lines:
        try:
            line = ida["lines"].generate_disasm_line(ea, 0)
        except Exception:
            break
        if not line:
            break
        try:
            text = ida["lines"].tag_remove(line)
        except Exception:
            text = str(line)
        lines.append("%s  %s" % (_fmt_ea(ea), text))
        try:
            insn = ida["ua"].insn_t()
            size = ida["ua"].decode_insn(insn, ea)
        except Exception:
            size = 0
        ea += size if size > 0 else 1
    return lines


def _disasm_func(func_ea: int, max_lines: int = 800) -> list[str]:
    ida = _ida()
    f = ida["funcs"].get_func(func_ea)
    if not f:
        return []
    return _disasm_range(f.start_ea, f.end_ea, max_lines)


def _cfunc(func_ea: int, max_lines: int = 2000) -> str:
    """Decompile func_ea to C text via Hex-Rays."""
    ida = _ida()
    try:
        f = ida["funcs"].get_func(func_ea)
        if not f:
            return ""
        cf = ida["hexrays"].decompile(f)
    except Exception as e:
        return f"<hexrays unavailable: {e}>"
    if cf is None:
        return "<hexrays failed to decompile this function>"
    try:
        body = cf.get_pseudocode() if hasattr(cf, "get_pseudocode") else []
        parts = []
        for l in body:
            line = getattr(l, "line", None)
            if line is None:
                line = str(l)
            line = str(line)
            # Strip IDA colour tags / control chars that would otherwise render
            # as garbage glyphs in the chat view.
            try:
                line = ida["lines"].tag_remove(line)
            except Exception:
                line = _strip_control_chars(line)
            parts.append(line.rstrip())
        return "\n".join(parts[:max_lines])
    except Exception as e:
        return f"<error reading pseudocode: {e}>"



# ---------------------------------------------------------------------------
# Reading tools
# ---------------------------------------------------------------------------


@ida_tool()
async def get_ea_by_name(ctx: RunContext, name: str) -> str:
    """Resolve a symbol name to its address (hex). Returns 'not found' if absent."""
    ida = _ida()
    bad = ida["idaapi"].BADADDR
    ea = ida["name"].get_name_ea(bad, name)
    return _fmt_ea(ea) if ea != bad else f"not found: {name}"


@ida_tool()
async def get_name_at_ea(ctx: RunContext, ea: str) -> str:
    """Get the symbol name (if any) at an address."""
    ida = _ida()
    a = _ea_of(ea)
    n = ida["name"].get_name(a) or ""
    return n if n else "(no name)"


@ida_tool()
async def get_current_ea(ctx: RunContext) -> str:
    """Return the current cursor address in IDA (hex)."""
    ida = _ida()
    ea = ida["kernwin"].get_screen_ea()
    return _fmt_ea(ea)


@ida_tool()
async def get_function_list(ctx: RunContext, name_filter: str = "") -> str:
    """List all functions, optionally filtered by substring in the name."""
    ida = _ida()
    out = []
    for idx in range(ida["funcs"].get_func_qty()):
        f = ida["funcs"].getn_func(idx)
        if not f:
            continue
        n = ida["funcs"].get_func_name(f.start_ea) or ""
        if name_filter and name_filter.lower() not in n.lower():
            continue
        out.append("%s %s" % (_fmt_ea(f.start_ea), n))
    return "\n".join(out[:2000]) if out else "(no functions)"


@ida_tool()
async def get_segments(ctx: RunContext) -> str:
    """List memory segments with name, start, end, and permissions."""
    ida = _ida()
    out = []
    seg = ida["segment"].get_first_seg()
    while seg:
        perms = []
        if seg.perm & ida["segment"].SEGPERM_READ:
            perms.append("R")
        if seg.perm & ida["segment"].SEGPERM_WRITE:
            perms.append("W")
        if seg.perm & ida["segment"].SEGPERM_EXEC:
            perms.append("X")
        out.append("%s %s-%s %s" % (ida["segment"].get_segm_name(seg) or "(no name)", _fmt_ea(seg.start_ea), _fmt_ea(seg.end_ea), "".join(perms)))
        seg = ida["segment"].get_next_seg(seg.start_ea)
    return "\n".join(out) if out else "(no segments)"


@ida_tool()
async def get_strings(ctx: RunContext, substring: str = "") -> str:
    """List strings in the binary, optionally filtered by substring."""
    ida = _ida()
    out = []
    try:
        for s in ida["autils"].Strings():
            text = "%s len=%d %s" % (hex(s.ea), s.length, repr(str(s)[:120]))
            if substring and substring.lower() not in text.lower():
                continue
            out.append(text)
    except Exception as e:
        return "(string listing failed: %s)" % e
    return "\n".join(out[:2000]) if out else "(no strings)"


@ida_tool()
async def get_xrefs_to(ctx: RunContext, name_or_ea: str) -> str:
    """List code/data references TO the given address or symbol."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    if not a:
        return "cannot resolve target"
    out = []
    xb = ida["xref"].xrefblk_t()
    ok = xb.first_to(a, 0)
    while ok:
        out.append("%s -> %s  (code=%s)" % (_fmt_ea(xb.frm), _fmt_ea(xb.to), xb.iscode))
        ok = xb.next_to()
    return "\n".join(out[:1000]) if out else "(no xrefs to this address)"


@ida_tool()
async def get_xrefs_from(ctx: RunContext, name_or_ea: str) -> str:
    """List references FROM the given address or symbol."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    if not a:
        return "cannot resolve source"
    out = []
    xb = ida["xref"].xrefblk_t()
    ok = xb.first_from(a, 0)
    while ok:
        out.append("%s -> %s  (code=%s)" % (_fmt_ea(xb.frm), _fmt_ea(xb.to), xb.iscode))
        ok = xb.next_from()
    return "\n".join(out[:1000]) if out else "(no xrefs from this address)"


@ida_tool()
async def get_function_info(ctx: RunContext, name_or_ea: str) -> str:
    """Get details about a function: address range, prototype, and comment."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    f = ida["funcs"].get_func(a)
    if not f:
        return "no function at this address"
    n = ida["funcs"].get_func_name(f.start_ea) or "(unnamed)"
    proto = ida["typeinf"].print_type(f.start_ea, ida["typeinf"].PRTYPE_1LINE | ida["typeinf"].PRTYPE_SEMI) or "(unknown prototype)"
    cmt = ida["funcs"].get_func_cmt(f, True) or ida["funcs"].get_func_cmt(f, False) or ""
    return "%s @ %s\nrange: %s-%s\nprototype: %s\ncomment: %s" % (n, _fmt_ea(f.start_ea), _fmt_ea(f.start_ea), _fmt_ea(f.end_ea), proto, cmt)


@ida_tool()
async def get_disassembly(ctx: RunContext, name_or_ea: str, count: int = 40) -> str:
    """Disassemble instructions starting at the given address (or symbol), 'count' lines total."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    f = ida["funcs"].get_func(a)
    if f:
        start, end = a, f.end_ea
    else:
        start, end = a, a + count * 8
    lines = _disasm_range(start, end, count)
    return "\n".join(lines) if lines else "(no instructions here)"


@ida_tool()
async def get_function_disassembly(ctx: RunContext, name_or_ea: str) -> str:
    """Disassemble an entire function at the given address or symbol."""
    a = _ea_of(name_or_ea)
    lines = _disasm_func(a)
    return "\n".join(lines) if lines else "no function at this address"


@ida_tool()
async def get_pseudocode(ctx: RunContext, name_or_ea: str) -> str:
    """Decompile the function containing the given address/symbol to pseudocode (C)."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    text = _cfunc(a)
    if not text:
        f = ida["funcs"].get_func(a)
        if f:
            text = _cfunc(f.start_ea)
    return text or "(no function at this address or decompiler unavailable)"


@ida_tool()
async def get_data_info(ctx: RunContext, name_or_ea: str, length: int = 32) -> str:
    """Inspect data at an address: bytes, size, type, and printable string form."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    length = min(max(int(length), 1), 256)
    n = ida["name"].get_name(a) or ""
    tstr = ""
    tif = ida["typeinf"].tinfo_t()
    if ida["typeinf"].guess_tinfo(tif, a) == ida["typeinf"].GUESS_FUNC_OK:
        try:
            tstr = ida["typeinf"].print_tinfo("", 0, 0, ida["typeinf"].PRTYPE_1LINE | ida["typeinf"].PRTYPE_SEMI, tif, n, "") or tif.dstr()
        except Exception:
            tstr = ""
    try:
        blob = ida["bytes"].get_bytes(a, length)
        if blob:
            hexs = " ".join("%02X" % b for b in blob)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in blob)
        else:
            hexs, asc = "(unreadable)", ""
    except Exception:
        hexs, asc = "(unreadable)", ""
    return "%s\nname: %s\ntype: %s\nbytes(%d): %s\nascii: %s" % (_fmt_ea(a), n, tstr or "(unknown)", length, hexs, asc)


@ida_tool()
async def get_type_info(ctx: RunContext, type_name: str) -> str:
    """Print a named type (struct/union/enum/typedef) from the local type library."""
    ida = _ida()
    til = ida["typeinf"].get_idati()
    tif = til.get_named_type(type_name)
    if not tif:
        return "no such named type: %s" % type_name
    name = tif.get_type_name() or type_name
    try:
        return ida["typeinf"].print_tinfo("", 0, 0, ida["typeinf"].PRTYPE_1LINE | ida["typeinf"].PRTYPE_DEF | ida["typeinf"].PRTYPE_SEMI, tif, name, "")
    except Exception:
        return tif.dstr() if hasattr(tif, "dstr") else str(tif)


@ida_tool()
async def get_comments(ctx: RunContext, name_or_ea: str) -> str:
    """Get the regular and repeatable comments at an address."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    reg = ida["bytes"].get_cmt(a, False) or ""
    rep = ida["bytes"].get_cmt(a, True) or ""
    return "regular: %s\nrepeatable: %s" % (reg, rep)


# ---------------------------------------------------------------------------
# Editing tools
# ---------------------------------------------------------------------------


def _refresh_ui() -> None:
    try:
        import ida_kernwin

        ida_kernwin.refresh_idaview_anyway()
    except Exception:
        pass


@ida_tool(write=True)
async def set_name(ctx: RunContext, name_or_ea: str, new_name: str, force: bool = False) -> str:
    """Rename the symbol at an address (or named symbol)."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    flags = ida["name"].SN_FORCE if force else 0
    ok = ida["name"].set_name(a, new_name, flags)
    _refresh_ui()
    return "renamed %s to %s" % (_fmt_ea(a), new_name) if ok else "failed to rename %s" % _fmt_ea(a)


@ida_tool(write=True)
async def set_comment(ctx: RunContext, name_or_ea: str, comment: str, repeatable: bool = False) -> str:
    """Set a comment at an address. Set repeatable=True for a repeatable comment."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    ok = ida["bytes"].set_cmt(a, comment, bool(repeatable))
    _refresh_ui()
    return "comment set at %s" % _fmt_ea(a) if ok else "failed to set comment at %s" % _fmt_ea(a)


@ida_tool(write=True)
async def set_function_comment(ctx: RunContext, name_or_ea: str, comment: str) -> str:
    """Set the comment of the function containing the given address/symbol."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    f = ida["funcs"].get_func(a)
    if not f:
        return "no function at this address"
    ok = ida["funcs"].set_func_cmt(f, comment, True)
    _refresh_ui()
    return "function comment set at %s" % _fmt_ea(f.start_ea) if ok else "failed to set function comment"


@ida_tool(write=True)
async def set_function_prototype(ctx: RunContext, name_or_ea: str, prototype: str) -> str:
    """Apply a C prototype to the function at the given address/symbol, e.g. 'int __cdecl foo(int a, char *b);'."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    f = ida["funcs"].get_func(a)
    if not f:
        return "no function at this address"
    ok = ida["typeinf"].apply_cdecl(ida["typeinf"].get_idati(), f.start_ea, prototype)
    _refresh_ui()
    return "prototype applied" if ok else "failed to apply prototype"


@ida_tool(write=True)
async def set_type_at_ea(ctx: RunContext, name_or_ea: str, declaration: str) -> str:
    """Apply a C type declaration to the data/object at an address, e.g. 'int[4]' or 'struct foo *'."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    ok = ida["typeinf"].apply_cdecl(ida["typeinf"].get_idati(), a, declaration)
    _refresh_ui()
    return "type applied at %s" % _fmt_ea(a) if ok else "failed to apply type at %s" % _fmt_ea(a)


@ida_tool(write=True)
async def set_variable_name(ctx: RunContext, function: str, old_name: str, new_name: str) -> str:
    """Rename a Hex-Rays local variable inside a function. 'function' is the function address or symbol."""
    ida = _ida()
    f = ida["funcs"].get_func(_ea_of(function))
    if not f:
        return "no function at %s" % function
    try:
        ok = ida["hexrays"].rename_lvar(f.start_ea, old_name, new_name)
    except Exception as e:
        return "hexrays rename failed: %s" % e
    _refresh_ui()
    return "renamed variable %s -> %s" % (old_name, new_name) if ok else "failed to rename variable %s" % old_name


@ida_tool(write=True)
async def set_variable_type(ctx: RunContext, function: str, variable: str, new_type: str) -> str:
    """Change the type of a Hex-Rays local variable in a function. new_type is a C type, e.g. 'int *'."""
    ida = _ida()
    f = ida["funcs"].get_func(_ea_of(function))
    if not f:
        return "no function at %s" % function
    try:
        loc = ida["hexrays"].lvar_locator_t()
        if not ida["hexrays"].locate_lvar(loc, f.start_ea, variable):
            return "could not locate variable %s in %s" % (variable, function)

        tif = ida["typeinf"].tinfo_t()
        if not tif.parse(new_type, ida["typeinf"].get_idati(), ida["typeinf"].PT_SIL):
            return "cannot parse type: %s" % new_type

        class _Mod(ida["hexrays"].user_lvar_modifier_t):
            def modify_lvars(self, lvinf):
                info = lvinf.find_info(loc)
                if not info:
                    return False
                info.type = tif
                info.size = tif.get_size()
                return True

        ok = ida["hexrays"].modify_user_lvars(f.start_ea, _Mod())
    except Exception as e:
        return "failed to change variable type: %s" % e
    _refresh_ui()
    return "changed type of %s to %s" % (variable, new_type) if ok else "failed to change variable type"


@ida_tool(write=True)
async def create_struct(ctx: RunContext, name: str, members: str) -> str:
    """Create a struct type. 'members' is a C-like member list, one per line: '<type> <name>'. E.g.: 'int x', 'char *y'."""
    ida = _ida()
    til = ida["typeinf"].get_idati()
    lines = []
    for raw in members.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        m = re.match(r"^(.*)([*\s]+)([A-Za-z_]\w*)\s*$", raw)
        if not m:
            return "invalid member line: %r (expected '<type> <name>')" % raw
        # Keep any '*' separators as part of the type (e.g. 'char *y' -> 'char *').
        type_part = (m.group(1) + m.group(2).replace(" ", "")).strip()
        lines.append("    %s %s;" % (type_part, m.group(3).strip()))
    if not lines:
        return "no members given"
    decl = "struct %s {\n%s\n};" % (name, "\n".join(lines))
    # printer may be None (a.k.a. nullptr) - parse errors are reported via the
    # returned count rather than a callback.
    errs = ida["typeinf"].parse_decls(til, decl, None, ida["typeinf"].HTI_DCL | ida["typeinf"].HTI_NER)
    _refresh_ui()
    return "struct %s created (parse_errors=%d)" % (name, errs) if errs == 0 else "failed to create struct %s (%d errors)" % (name, errs)


@ida_tool(write=True)
async def create_enum(ctx: RunContext, name: str, entries: str) -> str:
    """Create a named enum type. 'entries' is 'name=value' one per line."""
    ida = _ida()
    til = ida["typeinf"].get_idati()
    lines = []
    for raw in entries.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        if "=" not in raw:
            return "invalid enum entry (expected name=value): %r" % raw
        en, ev = raw.split("=", 1)
        lines.append("    %s = %s," % (en.strip(), ev.strip()))
    if not lines:
        return "no entries given"
    decl = "enum %s { %s };" % (name, "\n".join(lines))
    errs = ida["typeinf"].parse_decls(til, decl, None, ida["typeinf"].HTI_DCL | ida["typeinf"].HTI_NER)
    _refresh_ui()
    return "enum %s created (parse_errors=%d)" % (name, errs) if errs == 0 else "failed to create enum %s (%d errors)" % (name, errs)


def _udt_for(ida: dict[str, Any], type_name: str):
    """Look up a named struct/union and return its editable tinfo_t."""
    til = ida["typeinf"].get_idati()
    tif = til.get_named_type(type_name)
    if not tif:
        raise ValueError("no such named type: %s" % type_name)
    if not (tif.is_struct() or tif.is_union()):
        raise ValueError("%s is not a struct/union" % type_name)
    tif.detach()  # make a private copy so edits are not half-applied on error
    return til, tif


@ida_tool(write=True)
async def add_struct_member(ctx: RunContext, struct_name: str, field_type: str, field_name: str) -> str:
    """Add a member to an existing struct/union type."""
    ida = _ida()
    try:
        til, tif = _udt_for(ida, struct_name)
        mtype = ida["typeinf"].tinfo_t()
        if not mtype.parse(field_type, til, ida["typeinf"].PT_SIL):
            return "cannot parse field type: %s" % field_type
        tif.add_udm(field_name, mtype)
    except Exception as e:
        return "failed to add member: %s" % e
    _refresh_ui()
    return "added member %s : %s to %s" % (field_name, field_type, struct_name)


@ida_tool(write=True)
async def rename_struct_member(ctx: RunContext, struct_name: str, old_name: str, new_name: str) -> str:
    """Rename a member of an existing struct/union type."""
    ida = _ida()
    try:
        til, tif = _udt_for(ida, struct_name)
        udt = ida["typeinf"].udt_type_data_t()
        if not tif.get_udt_details(udt):
            return "could not read members of %s" % struct_name
        idx = udt.find_member(old_name)
        if idx < 0:
            return "member %s not found in %s" % (old_name, struct_name)
        tif.rename_udm(idx, new_name)
    except Exception as e:
        return "failed to rename member: %s" % e
    _refresh_ui()
    return "renamed %s.%s to %s" % (struct_name, old_name, new_name)


@ida_tool(write=True)
async def del_struct_member(ctx: RunContext, struct_name: str, member_name: str) -> str:
    """Delete a member from an existing struct/union type."""
    ida = _ida()
    try:
        til, tif = _udt_for(ida, struct_name)
        udt = ida["typeinf"].udt_type_data_t()
        if not tif.get_udt_details(udt):
            return "could not read members of %s" % struct_name
        idx = udt.find_member(member_name)
        if idx < 0:
            return "member %s not found in %s" % (member_name, struct_name)
        tif.del_udm(idx)
    except Exception as e:
        return "failed to delete member: %s" % e
    _refresh_ui()
    return "deleted member %s.%s" % (struct_name, member_name)


@ida_tool(write=True)
async def apply_struct_type(ctx: RunContext, name_or_ea: str, struct_name: str) -> str:
    """Apply a named struct/union type to the object at an address."""
    ida = _ida()
    a = _ea_of(name_or_ea)
    til = ida["typeinf"].get_idati()
    tif = til.get_named_type(struct_name)
    if not tif:
        return "no such named type: %s" % struct_name
    ok = ida["typeinf"].apply_tinfo(a, tif, ida["typeinf"].TINFO_DEFINITE)
    _refresh_ui()
    return "applied %s at %s" % (struct_name, _fmt_ea(a)) if ok else "failed to apply %s at %s" % (struct_name, _fmt_ea(a))


@ida_tool()
async def list_local_types(ctx: RunContext) -> str:
    """List all named types (structs, enums, typedefs) in the local type library."""
    ida = _ida()
    til = ida["typeinf"].get_idati()
    names = sorted(til.type_names) if hasattr(til, "type_names") else []
    return "\n".join(names) if names else "(no local types)"


# ---------------------------------------------------------------------------
# IDAPython execution tool
# ---------------------------------------------------------------------------


def _ida_python_import(name: str, globals=None, locals=None, fromlist=(), level=0):
    """Restricted __import__ for the IDAPython sandbox.

    Only IDA-related modules may be imported; anything else (os, sys,
    subprocess, socket, requests, urllib, ctypes, ...) is blocked so the code
    cannot escape to the host OS.
    """
    if level != 0:
        raise ImportError("relative imports are not allowed")
    base = name.split(".")[0]
    if not (base.startswith("ida_") or base in ("idc", "idautils", "idaapi")):
        raise ImportError("import not allowed: %r (IDA modules only)" % name)
    return __import__(name, globals, locals, fromlist, level)


async def run_idapython(ctx: RunContext, code: str) -> str:
    """Execute IDAPython code against the current database.

    Runs on IDA's main thread, so it can use any IDA API (ida_funcs,
    ida_bytes, ida_name, idc, idautils, ...) and freely read/modify the
    database. The modules ``idaapi``, ``idc`` and ``idautils`` are
    pre-imported. Only IDA modules may be imported - host modules (os, sys,
    subprocess, socket, requests, ...) are blocked. Output printed via
    ``print()`` is returned.

    NOTE: keep snippets short. An infinite loop would occupy IDA's main thread
    until interrupted, just like a hand-typed IDAPython script.
    """
    import builtins
    import contextlib
    import io

    def _run() -> str:
        buf = io.StringIO()
        orig_import = builtins.__import__
        try:
            namespace = {
                "__builtins__": builtins,
                "__name__": "__ida_copilot__",
            }
            # Pre-import the IDA modules the model is most likely to need.
            for mod in ("idaapi", "idc", "idautils", "ida_funcs", "ida_bytes",
                        "ida_name", "ida_nalt", "ida_xref", "ida_kernwin"):
                try:
                    namespace[mod] = __import__(mod)
                except Exception:
                    namespace[mod] = None
            builtins.__import__ = _ida_python_import
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                exec(compile(code, "<ida_copilot>", "exec"), namespace, namespace)  # noqa: S102
            return buf.getvalue().rstrip() or "(no output)"
        except BaseException as e:  # noqa: BLE001
            return f"error: {type(e).__name__}: {e}"
        finally:
            builtins.__import__ = orig_import

    return _strip_control_chars(_run_on_main(_run, write=True))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

IDA_TOOLS = [
    get_ea_by_name,
    get_name_at_ea,
    get_current_ea,
    get_function_list,
    get_segments,
    get_strings,
    get_xrefs_to,
    get_xrefs_from,
    get_function_info,
    get_disassembly,
    get_function_disassembly,
    get_pseudocode,
    get_data_info,
    get_type_info,
    get_comments,
    set_name,
    set_comment,
    set_function_comment,
    set_function_prototype,
    set_type_at_ea,
    set_variable_name,
    set_variable_type,
    create_struct,
    create_enum,
    add_struct_member,
    rename_struct_member,
    del_struct_member,
    apply_struct_type,
    list_local_types,
    run_idapython,
]
