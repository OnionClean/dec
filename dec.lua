--[[
    Universal Roblox Luau Bytecode Decompiler V2
    Built for exploit environments with getscriptbytecode access
    Usage: decompilev2(script_instance_or_path)
    
    Fixed version with proper bytecode parsing
]]

local LuauDecompiler = {}

-- Luau opcodes (complete set from Luau VM)
local OpCodes = {
    [0] = "NOP", [1] = "BREAK", [2] = "LOADNIL", [3] = "LOADB", [4] = "LOADN", [5] = "LOADK",
    [6] = "MOVE", [7] = "GETGLOBAL", [8] = "SETGLOBAL", [9] = "GETUPVAL", [10] = "SETUPVAL",
    [11] = "CLOSEUPVALS", [12] = "GETIMPORT", [13] = "GETTABLE", [14] = "SETTABLE", [15] = "GETTABLEKS",
    [16] = "SETTABLEKS", [17] = "GETTABLEN", [18] = "SETTABLEN", [19] = "NEWCLOSURE", [20] = "NAMECALL",
    [21] = "CALL", [22] = "RETURN", [23] = "JUMP", [24] = "JUMPBACK", [25] = "JUMPIF",
    [26] = "JUMPIFNOT", [27] = "JUMPIFEQ", [28] = "JUMPIFLE", [29] = "JUMPIFLT", [30] = "JUMPIFNOTEQ",
    [31] = "JUMPIFNOTLE", [32] = "JUMPIFNOTLT", [33] = "ADD", [34] = "SUB", [35] = "MUL",
    [36] = "DIV", [37] = "MOD", [38] = "POW", [39] = "ADDK", [40] = "SUBK",
    [41] = "MULK", [42] = "DIVK", [43] = "MODK", [44] = "POWK", [45] = "AND",
    [46] = "OR", [47] = "ANDK", [48] = "ORK", [49] = "CONCAT", [50] = "NOT",
    [51] = "MINUS", [52] = "LENGTH", [53] = "NEWTABLE", [54] = "DUPTABLE", [55] = "SETLIST",
    [56] = "FORNPREP", [57] = "FORNLOOP", [58] = "FORGLOOP", [59] = "FORGPREP_INEXT", [60] = "FASTCALL3",
    [61] = "FORGPREP_NEXT", [62] = "NATIVECALL", [63] = "GETVARARGS", [64] = "DUPCLOSURE", [65] = "PREPVARARGS",
    [66] = "LOADKX", [67] = "JUMPX", [68] = "FASTCALL", [69] = "COVERAGE", [70] = "CAPTURE",
    [71] = "SUBRK", [72] = "DIVRK", [73] = "FASTCALL1", [74] = "FASTCALL2", [75] = "FASTCALL2K",
    [76] = "FORGPREP", [77] = "JUMPXEQKNIL", [78] = "JUMPXEQKB", [79] = "JUMPXEQKN", [80] = "JUMPXEQKS",
    [81] = "IDIV", [82] = "IDIVK"
}

-- Bytecode reader with proper varint support
function LuauDecompiler:ReadProto(reader, strings)
    local function parse(bodyHasFlags)
        local proto = {}
        proto.maxStackSize = reader:readByte() or 0
        proto.numParams = reader:readByte() or 0
        proto.numUpvals = reader:readByte() or 0
        proto.isVararg = (reader:readByte() or 0) ~= 0
        if bodyHasFlags then
            proto.flags = reader:readByte() or 0
            local typeInfoSize = reader:readVarInt()
            if typeInfoSize and typeInfoSize > 0 then
                reader.pos = reader.pos + typeInfoSize
            end
        end
        local instrCount = reader:readVarInt() or 0
        proto.instructions = {}
        for i = 1, instrCount do
            local instr = reader:readInt32()
            table.insert(proto.instructions, instr)
        end
        local constCount = reader:readVarInt() or 0
        proto.constants = {}
        for i = 1, constCount do
            local constType = reader:readByte() or 0
            local value
            if constType == 0 then
                value = nil
            elseif constType == 1 then
                local b = reader:readByte() or 0
                value = (b ~= 0)
            elseif constType == 2 then
                value = reader:readDouble()
            elseif constType == 3 then
                local strIdx = reader:readVarInt() or 0
                value = strings[(strIdx or 0) + 1]
            elseif constType == 4 then
                local id = reader:readVarInt() or 0
                value = { type = "import", id = id }
            elseif constType == 5 then
                local keys = reader:readVarInt() or 0
                value = { type = "table", size = keys }
                for j = 1, keys do reader:readVarInt() end
            elseif constType == 6 then
                local protoIdx = reader:readVarInt() or 0
                value = { type = "closure", proto = protoIdx }
            else
                value = nil
            end
            table.insert(proto.constants, value)
        end
        local debugSize = reader:readVarInt() or 0
        if debugSize > 0 then reader.pos = reader.pos + debugSize end
        return proto
    end

    local savePos = reader.pos
    local ok, proto = pcall(parse, false)
    if ok and proto and #proto.instructions > 0 then
        return proto
    end
    -- fallback with flags/type info
    reader.pos = savePos
    local ok2, proto2 = pcall(parse, true)
    if ok2 and proto2 then
        return proto2
    end
    -- as last resort, return empty proto
    return { maxStackSize = 0, numParams = 0, numUpvals = 0, isVararg = false, instructions = {}, constants = {} }
end
        local b1, b2, b3, b4 = string.byte(self.data, self.pos, self.pos + 3)
        self.pos = self.pos + 4
        return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
    end
    
    function reader:readBytes(len)
        if self.pos + len - 1 > #self.data then
            error("readBytes exceeds bytecode size")
        end
        local s = string.sub(self.data, self.pos, self.pos + len - 1)
        self.pos = self.pos + len
        return s
    end
    
    function reader:hasMore()
        return self.pos <= #self.data
    end
    
    return reader
end

-- Parse Luau bytecode with proper format
function LuauDecompiler:ParseBytecode(bytecode)
    local reader = self:CreateReader(bytecode)
    local result = {}
    
    -- Read header
    local version = reader:readByte()
    if version < 3 or version > 6 then
        error("Unsupported bytecode version: " .. version)
    end
    result.version = version
    
    -- Read string table (blob + offsets)
    -- Layout: [stringDataSize][stringData][stringCount][offsets...] where 
    -- each string at offset starts with varint length followed by bytes
    local stringDataSize = reader:readVarInt()
    local stringData = reader:readBytes(stringDataSize)
    local stringCount = reader:readVarInt()
    if stringCount > 200000 then error("Invalid string count: " .. stringCount) end
    local offsets = {}
    for i = 1, stringCount do
        offsets[i] = reader:readVarInt()
    end
    
    local function readVarIntFromBlob(blob, pos)
        local res, shift = 0, 0
        local i = pos
        while true do
            local b = string.byte(blob, i)
            i = i + 1
            res = res + bit32.lshift(bit32.band(b, 0x7F), shift)
            if bit32.band(b, 0x80) == 0 then break end
            shift = shift + 7
        end
        return res, i
    end
    
    result.strings = {}
    for i = 1, stringCount do
        local off = offsets[i] + 1 -- 1-based in Lua
        local len, nextPos = readVarIntFromBlob(stringData, off)
        local s = string.sub(stringData, nextPos, nextPos + len - 1)
        result.strings[i] = s
    end
    
    -- Read proto table count
    local protoCount = reader:readVarInt()
    if protoCount > 10000 then -- Sanity check
        error("Invalid proto count: " .. protoCount)
    end
    
    result.protos = {}
    
    -- Read main proto first
    local mainProto = self:ReadProto(reader, result.strings)
    table.insert(result.protos, mainProto)
    
    -- Read child protos
    for i = 2, protoCount do
        local proto = self:ReadProto(reader, result.strings)
        table.insert(result.protos, proto)
    end
    
    result.mainProto = result.protos[1]
    return result
end

-- Read a single proto (function)
function LuauDecompiler:ReadProto(reader, strings)
    local proto = {}
    
    -- Read proto header
    proto.maxStackSize = reader:readByte()
    proto.numParams = reader:readByte()
    proto.numUpvals = reader:readByte()
    proto.isVararg = reader:readByte() ~= 0
    
    -- Flags byte (new in recent versions)
    if reader:hasMore() then
        proto.flags = reader:readByte()
    end
    
    -- Read type info if present
    local typeInfoSize = reader:readVarInt()
    if typeInfoSize > 0 then
        -- Skip type info for now
        reader.pos = reader.pos + typeInfoSize
    end
    
    -- Read instructions
    local instrCount = reader:readVarInt()
    proto.instructions = {}
    for i = 1, instrCount do
        local instr = reader:readInt32()
        table.insert(proto.instructions, instr)
    end
    
    -- Read constants
    local constCount = reader:readVarInt()
    proto.constants = {}
    for i = 1, constCount do
        local constType = reader:readByte()
        local value
        -- Tags based on Luau BytecodeTag: 0=nil,1=bool,2=number,3=string,4=import,5=table,6=function
        if constType == 0 then
            value = nil
        elseif constType == 1 then
            local b = reader:readByte()
            value = (b ~= 0)
        elseif constType == 2 then
            value = reader:readDouble()
        elseif constType == 3 then
            local strIdx = reader:readVarInt()
            value = strings[(strIdx or 0) + 1]
        elseif constType == 4 then
            -- import: refer to GETIMPORT path indices; keep as placeholder
            local id = reader:readVarInt()
            value = { type = "import", id = id }
        elseif constType == 5 then
            -- table template: skip payload for now
            local keys = reader:readVarInt()
            value = { type = "table", size = keys }
            for j = 1, keys do reader:readVarInt() end
        elseif constType == 6 then
            local protoIdx = reader:readVarInt()
            value = { type = "closure", proto = protoIdx }
        else
            value = nil
        end
        
        table.insert(proto.constants, value)
    end
    
    -- Read debug info size and skip it
    local debugSize = reader:readVarInt()
    if debugSize > 0 then
        reader.pos = reader.pos + debugSize
    end
    
    return proto
end

-- Instruction decoding helpers
local function INSN_OP(insn) return bit32.band(insn, 0xFF) end
local function INSN_A(insn) return bit32.band(bit32.rshift(insn, 8), 0xFF) end
local function INSN_B(insn) return bit32.band(bit32.rshift(insn, 16), 0xFF) end
local function INSN_C(insn) return bit32.band(bit32.rshift(insn, 24), 0xFF) end
local function INSN_D(insn) return bit32.rshift(insn, 16) end
local function INSN_E(insn) return bit32.rshift(insn, 8) end

-- Decompile a single instruction
-- Structured decompilation with AUX handling and expression building
local AUX_OPS = {
    GETGLOBAL = true, SETGLOBAL = true, GETIMPORT = true, GETTABLEKS = true, SETTABLEKS = true,
    NAMECALL = true, SETLIST = true, LOADKX = true, JUMPX = true, JUMPIFEQ = true, JUMPIFLE = true,
    JUMPIFLT = true, JUMPIFNOTEQ = true, JUMPIFNOTLE = true, JUMPIFNOTLT = true, JUMPXEQKNIL = true,
    JUMPXEQKB = true, JUMPXEQKN = true, JUMPXEQKS = true, FASTCALL3 = true, FASTCALL2 = true,
}

local function needsAux(opname)
    return AUX_OPS[opname] == true
end

local function decodeAuxPath(aux)
    -- AUX packs up to 3 10-bit indices, top 2 bits store path length (1..3)
    local len = bit32.rshift(aux, 30)
    if len < 1 or len > 3 then len = 1 end
    local idx1 = bit32.band(aux, 0x3FF)
    local idx2 = bit32.band(bit32.rshift(aux, 10), 0x3FF)
    local idx3 = bit32.band(bit32.rshift(aux, 20), 0x3FF)
    local idxs = {idx1}
    if len >= 2 then table.insert(idxs, idx2) end
    if len >= 3 then table.insert(idxs, idx3) end
    return idxs
end

local function quote(s)
    if type(s) ~= "string" then return tostring(s) end
    return string.format("%q", s)
end

function LuauDecompiler:DecompileStructured(proto, bytecodeInfo)
    local out = {}
    local regs = {}
    local declared = {}
    local function setreg(r, expr)
        regs[r] = expr
        if not declared[r] then
            table.insert(out, string.format("local R%d = %s", r, expr))
            declared[r] = true
        else
            table.insert(out, string.format("R%d = %s", r, expr))
        end
    end
    local function getreg(r)
        return regs[r] or ("R" .. r)
    end

    local i = 1
    local n = #proto.instructions
    local lastClosure -- track most recent NEWCLOSURE for CAPTUREs
    while i <= n do
        local instr = proto.instructions[i]
        local op = INSN_OP(instr)
        local opname = OpCodes[op] or ("UNKNOWN_" .. op)
        local A, B, C, D = INSN_A(instr), INSN_B(instr), INSN_C(instr), INSN_D(instr)
        local aux, consumed = nil, 1
        if needsAux(opname) and (i + 1) <= n then
            aux = proto.instructions[i + 1]
            consumed = 2
        end

        if opname == "LOADNIL" then
            setreg(A, "nil")
        elseif opname == "LOADB" then
            setreg(A, B ~= 0 and "true" or "false")
        elseif opname == "LOADN" then
            setreg(A, tostring(bit32.rshift(instr, 16)))
        elseif opname == "LOADK" then
            local k = proto.constants[D + 1]
            if type(k) == "string" then
                setreg(A, quote(k))
            elseif type(k) == "number" then
                setreg(A, tostring(k))
            elseif type(k) == "boolean" then
                setreg(A, tostring(k))
            else
                setreg(A, "nil")
            end
        elseif opname == "LOADKX" and aux then
            local idx = aux
            local k = proto.constants[(idx or 0) + 1]
            setreg(A, type(k) == "string" and quote(k) or tostring(k))
        elseif opname == "MOVE" then
            setreg(A, getreg(B))
        elseif opname == "GETGLOBAL" and aux then
            local nameIdx = aux
            local name = proto.constants[(nameIdx or 0) + 1]
            name = type(name) == "string" and name or ("CONST_" .. tostring(nameIdx or 0))
            setreg(A, string.format("_G[%s]", quote(name)))
        elseif opname == "SETGLOBAL" and aux then
            local nameIdx = aux
            local name = proto.constants[(nameIdx or 0) + 1]
            name = type(name) == "string" and name or ("CONST_" .. tostring(nameIdx or 0))
            table.insert(out, string.format("_G[%s] = %s", quote(name), getreg(A)))
        elseif opname == "GETTABLE" then
            setreg(A, string.format("%s[%s]", getreg(B), getreg(C)))
        elseif opname == "SETTABLE" then
            table.insert(out, string.format("%s[%s] = %s", getreg(B), getreg(C), getreg(A)))
    elseif opname == "GETTABLEKS" and aux then
            local keyIdx = aux
            local key = proto.constants[(keyIdx or 0) + 1]
            if type(key) ~= "string" then key = tostring(key) end
            setreg(A, string.format("%s.%s", getreg(B), key))
        elseif opname == "SETTABLEKS" and aux then
            local keyIdx = aux
            local key = proto.constants[(keyIdx or 0) + 1]
            if type(key) ~= "string" then key = tostring(key) end
            table.insert(out, string.format("%s.%s = %s", getreg(B), key, getreg(A)))
        elseif opname == "GETIMPORT" then
            -- Build from AUX path if available, else from D as constant index
            local expr = ""
            if aux then
                local idxs = decodeAuxPath(aux)
                local parts = {}
                for _, idx in ipairs(idxs) do
                    local s = bytecodeInfo.strings[(idx or 0) + 1]
                    table.insert(parts, type(s) == "string" and s or ("STR_" .. tostring(idx)))
                end
                -- Heuristic build: game:GetService("X") vs script.Parent etc.
                if parts[1] == "game" and parts[2] == "GetService" and parts[3] then
                    expr = string.format("game:GetService(%s)", quote(parts[3]))
                elseif parts[1] == "workspace" then
                    expr = "workspace"
                elseif parts[1] == "script" then
                    if parts[2] then expr = "script." .. parts[2] else expr = "script" end
                else
                    expr = table.concat(parts, ".")
                end
            else
                local k = proto.constants[D + 1]
                expr = type(k) == "string" and k or "import"
            end
            setreg(A, expr)
        elseif opname == "NEWCLOSURE" then
            -- D is child proto index
            local childIdx = D
            local cl = { __closure = true, proto = childIdx, captures = {} }
            regs[A] = cl
            declared[A] = declared[A] or true
            lastClosure = cl
        elseif opname == "CAPTURE" then
            -- Capture upvalues for the last created closure
            if lastClosure then
                local src = getreg(B)
                table.insert(lastClosure.captures, src)
            end
        elseif opname == "NAMECALL" and aux then
            -- Prepare method call; actual call emitted on CALL
            local methodIdx = aux
            local method = proto.constants[(methodIdx or 0) + 1]
            if type(method) ~= "string" then method = tostring(methodIdx or "method") end
            -- Store a sentinel representing a prepared namecall
            regs[A] = { __namecall = true, obj = getreg(B), method = method }
            if not declared[A] then declared[A] = true end
        elseif opname == "CALL" then
            local funcExpr = regs[A]
            local args = {}
            -- args are in A+1..A+B-1
            for r = A + 1, A + math.max(B - 1, 0) do
                local ar = regs[r]
                if type(ar) == "table" and ar.__closure then
                    -- render inline closure with upvalue note
                    local upv = (#ar.captures > 0) and (" --[[ captures: " .. table.concat(ar.captures, ", ") .. " ]]") or ""
                    table.insert(args, "function(...) end" .. upv)
                else
                    table.insert(args, getreg(r))
                end
            end
            local callStr = nil
            if type(funcExpr) == "table" and funcExpr.__namecall then
                -- Convert NAMECALL into obj:method(args)
                local obj = funcExpr.obj
                -- First arg is self; drop it if it's obj
                if #args > 0 and args[1] == obj then table.remove(args, 1) end
                callStr = string.format("%s:%s(%s)", obj, funcExpr.method, table.concat(args, ", "))
            else
                callStr = string.format("%s(%s)", getreg(A), table.concat(args, ", "))
            end

            if C == 0 then
                table.insert(out, callStr)
            elseif C == 1 then
                table.insert(out, callStr)
            else
                -- Capture results into R[A..A+C-2]
                local rets = {}
                for r = A, A + C - 2 do table.insert(rets, "R" .. r) end
                for _, rname in ipairs(rets) do
                    local rnum = tonumber(rname:sub(2))
                    declared[rnum] = declared[rnum] or true
                end
                table.insert(out, string.format("local %s = %s", table.concat(rets, ", "), callStr))
                for idx, rname in ipairs(rets) do
                    local rnum = tonumber(rname:sub(2))
                    regs[rnum] = rname
                end
            end
        elseif opname == "NEWTABLE" then
            setreg(A, "{}")
        elseif opname == "DUPTABLE" then
            setreg(A, "{--[[template]]}")
        elseif opname == "CONCAT" then
            local parts = {}
            for r = B, C do table.insert(parts, getreg(r)) end
            setreg(A, table.concat(parts, " .. "))
        elseif opname == "NOT" then
            setreg(A, "not " .. getreg(B))
        elseif opname == "MINUS" then
            setreg(A, "-" .. getreg(B))
        elseif opname == "LENGTH" then
            setreg(A, "#" .. getreg(B))
        elseif opname == "RETURN" then
            if B == 0 or B == 1 then
                table.insert(out, "return")
            else
                local vals = {}
                for r = A, A + B - 2 do table.insert(vals, getreg(r)) end
                table.insert(out, "return " .. table.concat(vals, ", "))
            end
        elseif opname == "JUMPIF" or opname == "JUMPIFNOT" then
            -- Emit simple conditional; full structuring is out-of-scope here
            local cond = (opname == "JUMPIF") and getreg(A) or ("not " .. getreg(A))
            table.insert(out, string.format("if %s then --[[ jump %+d ]] end", cond, (bit32.rshift(instr,16)-32768)))
        elseif opname == "JUMP" or opname == "JUMPBACK" then
            table.insert(out, string.format("-- jump %+d", (bit32.rshift(instr,16)-32768)))
        
        else
            table.insert(out, string.format("-- %s A:%d B:%d C:%d D:%d", opname, A, B, C, D))
        end

        i = i + consumed
    end

    return table.concat(out, "\n")
end

-- Main decompilation
function LuauDecompiler:Decompile(proto, bytecodeInfo, level)
    level = level or 0
    local output = {}
    
    if level == 0 then
        table.insert(output, "-- Universal Luau Decompiler V2")
        table.insert(output, "-- Bytecode Version: " .. bytecodeInfo.version)
        table.insert(output, "-- String Count: " .. #bytecodeInfo.strings)
        table.insert(output, "-- Proto Count: " .. #bytecodeInfo.protos)
        table.insert(output, "")
        table.insert(output, "-- String Table:")
        for i, str in ipairs(bytecodeInfo.strings) do
            if i <= 20 then -- Show first 20 strings
                table.insert(output, string.format("-- [%d] = %q", i-1, str))
            end
        end
        if #bytecodeInfo.strings > 20 then
            table.insert(output, "-- ... and " .. (#bytecodeInfo.strings - 20) .. " more strings")
        end
        table.insert(output, "")
    end
    
    local indent = string.rep("  ", level)
    
    table.insert(output, indent .. "-- Function (params: " .. proto.numParams .. 
                         ", stack: " .. proto.maxStackSize .. 
                         ", upvals: " .. proto.numUpvals .. 
                         ", vararg: " .. tostring(proto.isVararg) .. ")")
    
    table.insert(output, indent .. "-- Instructions: " .. #proto.instructions)
    -- Use structured pass with AUX handling and expression reconstruction
    local body = self:DecompileStructured(proto, bytecodeInfo)
    for line in string.gmatch(body, "[^\n]+") do
        table.insert(output, indent .. line)
    end
    
    table.insert(output, "")
    
    return table.concat(output, "\n")
end

-- Main entry point
function decompilev2(input)
    local t0 = os.clock()
    local bytecode
    local outputPath
    
    -- Handle different input types
    if type(input) == "userdata" then
        -- Script instance
        if not getscriptbytecode then
            error("getscriptbytecode not available in this environment")
        end
        bytecode = getscriptbytecode(input)
        outputPath = (input.Name or "script") .. "_decompiled.lua"
    elseif type(input) == "string" then
        -- File path or raw bytecode
        if isfile and isfile(input) then
            bytecode = readfile(input)
            outputPath = input:gsub("%.%w+$", "") .. "_decompiled.lua"
        else
            -- Assume it's raw bytecode
            bytecode = input
            outputPath = "decompiled.lua"
        end
    else
        error("Invalid input type: expected script instance or file path")
    end
    
    if not bytecode or #bytecode == 0 then
        error("Failed to get bytecode or bytecode is empty")
    end
    
    print("🚀 Universal Luau Decompiler V3 - Structured")
    print("📊 Bytecode size: " .. #bytecode .. " bytes")
    
    -- Attempt decompilation
    local success, result = pcall(function()
        local bytecodeInfo = LuauDecompiler:ParseBytecode(bytecode)
    local decompiledCode = LuauDecompiler:Decompile(bytecodeInfo.mainProto, bytecodeInfo, 0)
    local elapsed = os.clock() - t0
    local header = string.format("-- Decompiled on %s\n-- Time taken: %.6f seconds\n", os.date("%Y-%m-%d %H:%M:%S"), elapsed)
    decompiledCode = header .. decompiledCode
        
        -- Add remaining protos
        for i = 2, #bytecodeInfo.protos do
            decompiledCode = decompiledCode .. "\n\n-- Proto " .. i .. "\n"
            decompiledCode = decompiledCode .. LuauDecompiler:Decompile(bytecodeInfo.protos[i], bytecodeInfo, 0)
        end
        
        -- Write to file if writefile is available
        if writefile then
            writefile(outputPath, decompiledCode)
            print("✅ Decompilation saved to: " .. outputPath)
        end
        
    print("✅ Decompilation completed!")
    print(string.format("⏱️ Time: %.6fs", elapsed))
        print("📏 Instructions processed: " .. #bytecodeInfo.mainProto.instructions)
        
        return decompiledCode
    end)
    
    if not success then
        error("Decompilation failed: " .. tostring(result))
    end
    
    return result
end

-- Set global
_G.decompilev2 = decompilev2

print("🌍 Universal Luau Decompiler V2 Loaded!")
print("💡 Usage: decompilev2(script_or_path)")

return LuauDecompiler
