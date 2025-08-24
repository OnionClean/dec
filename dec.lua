--[[
    Universal Roblox Luau Bytecode Decompiler V3
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

-- Create bytecode reader
function LuauDecompiler:CreateReader(data)
    local reader = { data = data, pos = 1 }
    
    function reader:readByte()
        if self.pos > #self.data then
            return nil
        end
        local b = string.byte(self.data, self.pos)
        self.pos = self.pos + 1
        return b
    end
    
    function reader:readVarInt()
        local result = 0
        local shift = 0
        while true do
            local b = self:readByte()
            if not b then return nil end
            result = result + bit32.lshift(bit32.band(b, 0x7F), shift)
            if bit32.band(b, 0x80) == 0 then
                break
            end
            shift = shift + 7
        end
        return result
    end
    
    function reader:readDouble()
        if self.pos + 7 > #self.data then
            return 0
        end
        local bytes = {string.byte(self.data, self.pos, self.pos + 7)}
        self.pos = self.pos + 8
        
        -- Convert bytes to double (simplified - may need proper IEEE 754 conversion)
        local sign = bit32.rshift(bytes[8], 7)
        local exponent = bit32.lshift(bit32.band(bytes[8], 0x7F), 4) + bit32.rshift(bytes[7], 4)
        local mantissa = bit32.band(bytes[7], 0x0F)
        
        for i = 6, 1, -1 do
            mantissa = mantissa * 256 + bytes[i]
        end
        
        if exponent == 0 then
            return 0
        elseif exponent == 0x7FF then
            return math.huge
        else
            local value = (1 + mantissa / 2^52) * 2^(exponent - 1023)
            return sign == 1 and -value or value
        end
    end
    
    function reader:readInt32()
        if self.pos + 3 > #self.data then
            return 0
        end
        local b1, b2, b3, b4 = string.byte(self.data, self.pos, self.pos + 3)
        self.pos = self.pos + 4
        return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
    end
    
    function reader:readString()
        -- Read null-terminated string
        local start = self.pos
        while self.pos <= #self.data do
            if string.byte(self.data, self.pos) == 0 then
                local str = string.sub(self.data, start, self.pos - 1)
                self.pos = self.pos + 1
                return str
            end
            self.pos = self.pos + 1
        end
        return string.sub(self.data, start)
    end
    
    function reader:readBytes(len)
        if self.pos + len - 1 > #self.data then
            return ""
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
    
    -- Try to detect format
    local firstByte = string.byte(bytecode, 1)
    local signature = reader:readBytes(4)
    reader.pos = 1 -- Reset position
    
    if signature == "RSB1" then
        -- Standard Luau bytecode format
        reader:readBytes(4) -- Skip signature
        result.version = reader:readByte()
        
        -- Read string table
        local stringCount = reader:readVarInt()
        result.strings = {}
        for i = 1, stringCount do
            local strLen = reader:readVarInt()
            if not strLen or strLen <= 0 then
                result.strings[i] = ""
            else
                local str = ""
                for j = 1, strLen do
                    local byte = reader:readByte()
                    if not byte then break end
                    str = str .. string.char(byte)
                end
                result.strings[i] = str
            end
        end
        
    else
        -- Alternative format - try to parse as direct string table
        result.version = 1
        result.strings = {}
        
        -- Try to extract strings directly
        local pos = 1
        local stringIndex = 1
        while pos <= #bytecode do
            local byte = string.byte(bytecode, pos)
            if byte >= 32 and byte <= 126 then -- Printable ASCII
                local str = ""
                while pos <= #bytecode do
                    local b = string.byte(bytecode, pos)
                    if b == 0 or b < 32 or b > 126 then
                        break
                    end
                    str = str .. string.char(b)
                    pos = pos + 1
                end
                if #str > 0 then
                    result.strings[stringIndex] = str
                    stringIndex = stringIndex + 1
                end
            end
            pos = pos + 1
        end
    end
    
    -- Read proto table count
    local protoCount = 0
    if signature == "RSB1" then
        protoCount = reader:readVarInt() or 0
        if protoCount > 10000 then
            error("Invalid proto count: " .. tostring(protoCount))
        end
    end
    
    result.protos = {}
    
    -- Read protos
    for i = 1, protoCount do
        local proto = self:ReadProto(reader, result.strings)
        table.insert(result.protos, proto)
    end
    
    result.mainProto = result.protos[1] or { instructions = {}, constants = {} }
    
    return result
end

-- Read a single proto (function)
function LuauDecompiler:ReadProto(reader, strings)
    local proto = {}
    
    -- Read proto header
    proto.maxStackSize = reader:readByte() or 0
    proto.numParams = reader:readByte() or 0
    proto.numUpvals = reader:readByte() or 0
    proto.isVararg = (reader:readByte() or 0) ~= 0
    
    -- Read flags byte if version >= 4
    proto.flags = reader:readByte() or 0
    
    -- Read type info size and skip it
    local typeInfoSize = reader:readVarInt() or 0
    if typeInfoSize > 0 then
        reader.pos = reader.pos + typeInfoSize
    end
    
    -- Read instructions
    local instrCount = reader:readVarInt() or 0
    proto.instructions = {}
    for i = 1, instrCount do
        local instr = reader:readInt32()
        if instr then
            table.insert(proto.instructions, instr)
        end
    end
    
    -- Read constants
    local constCount = reader:readVarInt() or 0
    proto.constants = {}
    for i = 1, constCount do
        local constType = reader:readByte()
        if not constType then break end
        local value
        
        if constType == 0 then -- nil
            value = nil
        elseif constType == 1 then -- boolean
            value = (reader:readByte() or 0) ~= 0
        elseif constType == 2 then -- number
            value = reader:readDouble()
        elseif constType == 3 then -- string
            local strIdx = reader:readVarInt() or 0
            value = strings[strIdx + 1] or ""
        elseif constType == 4 then -- import
            local id = reader:readVarInt() or 0
            value = { type = "import", id = id }
        elseif constType == 5 then -- table
            local keys = reader:readVarInt() or 0
            value = { type = "table", size = keys }
            for j = 1, keys do
                reader:readVarInt()
            end
        elseif constType == 6 then -- closure
            local protoIdx = reader:readVarInt() or 0
            value = { type = "closure", proto = protoIdx }
        else
            value = nil
        end
        
        table.insert(proto.constants, value)
    end
    
    -- Read debug info size and skip
    local debugSize = reader:readVarInt() or 0
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

-- Structured decompilation with AUX handling and expression building
local AUX_OPS = {
    GETGLOBAL = true, SETGLOBAL = true, GETIMPORT = true, GETTABLEKS = true, SETTABLEKS = true,
    NAMECALL = true, SETLIST = true, LOADKX = true, JUMPX = true, FASTCALL3 = true, FASTCALL2 = true,
}

local function needsAux(opname)
    return AUX_OPS[opname] == true
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
    local lastClosure = nil
    
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
            setreg(A, tostring(D))
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
            local k = proto.constants[aux + 1]
            setreg(A, type(k) == "string" and quote(k) or tostring(k))
        elseif opname == "MOVE" then
            setreg(A, getreg(B))
        elseif opname == "GETGLOBAL" and aux then
            local name = proto.constants[aux + 1]
            if type(name) == "string" then
                setreg(A, name)
            else
                setreg(A, "_G[?]")
            end
        elseif opname == "SETGLOBAL" and aux then
            local name = proto.constants[aux + 1]
            if type(name) == "string" then
                table.insert(out, string.format("%s = %s", name, getreg(A)))
            else
                table.insert(out, string.format("_G[?] = %s", getreg(A)))
            end
        elseif opname == "GETTABLE" then
            setreg(A, string.format("%s[%s]", getreg(B), getreg(C)))
        elseif opname == "SETTABLE" then
            table.insert(out, string.format("%s[%s] = %s", getreg(B), getreg(C), getreg(A)))
        elseif opname == "GETTABLEKS" and aux then
            local key = proto.constants[aux + 1]
            if type(key) == "string" then
                setreg(A, string.format("%s.%s", getreg(B), key))
            else
                setreg(A, string.format("%s[?]", getreg(B)))
            end
        elseif opname == "SETTABLEKS" and aux then
            local key = proto.constants[aux + 1]
            if type(key) == "string" then
                table.insert(out, string.format("%s.%s = %s", getreg(B), key, getreg(A)))
            else
                table.insert(out, string.format("%s[?] = %s", getreg(B), getreg(A)))
            end
        elseif opname == "GETIMPORT" then
            if aux then
                -- Decode import path from aux
                local count = bit32.rshift(aux, 30) + 1
                local id0 = bit32.band(aux, 0x3FF)
                local id1 = bit32.band(bit32.rshift(aux, 10), 0x3FF)
                local id2 = bit32.band(bit32.rshift(aux, 20), 0x3FF)
                
                local parts = {}
                if count >= 1 and bytecodeInfo.strings[id0 + 1] then
                    table.insert(parts, bytecodeInfo.strings[id0 + 1])
                end
                if count >= 2 and bytecodeInfo.strings[id1 + 1] then
                    table.insert(parts, bytecodeInfo.strings[id1 + 1])
                end
                if count >= 3 and bytecodeInfo.strings[id2 + 1] then
                    table.insert(parts, bytecodeInfo.strings[id2 + 1])
                end
                
                local expr = "import"
                if #parts > 0 then
                    if parts[1] == "game" and parts[2] == "GetService" and parts[3] then
                        expr = string.format("game:GetService(%q)", parts[3])
                    elseif parts[1] == "workspace" then
                        expr = "workspace"
                    else
                        expr = table.concat(parts, ".")
                    end
                end
                setreg(A, expr)
            else
                setreg(A, "import")
            end
        elseif opname == "NEWCLOSURE" then
            local childIdx = D
            local cl = { __closure = true, proto = childIdx, captures = {} }
            regs[A] = cl
            declared[A] = true
            lastClosure = cl
        elseif opname == "CAPTURE" then
            if lastClosure then
                table.insert(lastClosure.captures, getreg(B))
            end
        elseif opname == "NAMECALL" and aux then
            local method = proto.constants[aux + 1]
            if type(method) == "string" then
                regs[A] = { __namecall = true, obj = getreg(B), method = method }
                declared[A] = true
            end
        elseif opname == "CALL" then
            local funcExpr = regs[A]
            local args = {}
            
            for r = A + 1, A + B - 1 do
                local ar = regs[r]
                if type(ar) == "table" and ar.__closure then
                    local upv = (#ar.captures > 0) and (" --[[ captures: " .. table.concat(ar.captures, ", ") .. " ]]") or ""
                    table.insert(args, "function(...) end" .. upv)
                else
                    table.insert(args, getreg(r))
                end
            end
            
            local callStr
            if type(funcExpr) == "table" and funcExpr.__namecall then
                callStr = string.format("%s:%s(%s)", funcExpr.obj, funcExpr.method, table.concat(args, ", "))
            else
                callStr = string.format("%s(%s)", getreg(A), table.concat(args, ", "))
            end

            if C == 0 or C == 1 then
                table.insert(out, callStr)
            else
                local rets = {}
                for r = A, A + C - 2 do
                    table.insert(rets, "R" .. r)
                    declared[r] = true
                end
                table.insert(out, string.format("local %s = %s", table.concat(rets, ", "), callStr))
            end
        elseif opname == "RETURN" then
            if B == 0 or B == 1 then
                table.insert(out, "return")
            else
                local vals = {}
                for r = A, A + B - 2 do
                    table.insert(vals, getreg(r))
                end
                table.insert(out, "return " .. table.concat(vals, ", "))
            end
        elseif opname == "JUMP" then
            local offset = D - 32768
            table.insert(out, string.format("-- jump %+d", offset))
        elseif opname == "JUMPIF" then
            local offset = D - 32768
            table.insert(out, string.format("if %s then --[[ jump %+d ]] end", getreg(A), offset))
        elseif opname == "JUMPIFNOT" then
            local offset = D - 32768
            table.insert(out, string.format("if not %s then --[[ jump %+d ]] end", getreg(A), offset))
        elseif opname == "NEWTABLE" then
            setreg(A, "{}")
        elseif opname == "DUPTABLE" then
            setreg(A, "{}")
        elseif opname == "CONCAT" then
            local parts = {}
            for r = B, C do
                table.insert(parts, getreg(r))
            end
            setreg(A, table.concat(parts, " .. "))
        elseif opname == "NOT" then
            setreg(A, "not " .. getreg(B))
        elseif opname == "MINUS" then
            setreg(A, "-" .. getreg(B))
        elseif opname == "LENGTH" then
            setreg(A, "#" .. getreg(B))
        elseif opname == "ADD" then
            setreg(A, string.format("%s + %s", getreg(B), getreg(C)))
        elseif opname == "SUB" then
            setreg(A, string.format("%s - %s", getreg(B), getreg(C)))
        elseif opname == "MUL" then
            setreg(A, string.format("%s * %s", getreg(B), getreg(C)))
        elseif opname == "DIV" then
            setreg(A, string.format("%s / %s", getreg(B), getreg(C)))
        elseif opname == "MOD" then
            setreg(A, string.format("%s %% %s", getreg(B), getreg(C)))
        elseif opname == "POW" then
            setreg(A, string.format("%s ^ %s", getreg(B), getreg(C)))
        else
            table.insert(out, string.format("-- %s A:%d B:%d C:%d D:%d", opname, A, B, C, D))
        end

        i = i + consumed
    end

    return table.concat(out, "\n")
end

-- Main decompilation
function LuauDecompiler:ReconstructFromStrings(strings)
    local output = {}
    
    -- Look for common Roblox patterns in strings
    local gameServices = {}
    local events = {}
    local methods = {}
    local properties = {}
    
    for _, str in ipairs(strings) do
        if str then
            -- Detect game services
            if str:match("Service$") then
                table.insert(gameServices, str)
            -- Detect common events
            elseif str == "ChildAdded" or str == "ChildRemoved" or str == "Changed" or 
                   str == "Touched" or str == "Connect" or str == "MouseButton1Click" then
                table.insert(events, str)
            -- Detect common methods
            elseif str == "WaitForChild" or str == "GetChildren" or str == "FindFirstChild" or
                   str == "Clone" or str == "Destroy" or str == "GetService" then
                table.insert(methods, str)
            -- Detect properties
            elseif str == "Parent" or str == "Name" or str == "Text" or str == "Position" or
                   str == "Size" or str == "Visible" or str == "Enabled" then
                table.insert(properties, str)
            end
        end
    end
    
    -- Generate reconstructed code based on patterns
    if #gameServices > 0 then
        table.insert(output, "-- Game services detected:")
        for _, service in ipairs(gameServices) do
            table.insert(output, string.format('local %s = game:GetService("%s")', 
                         service:gsub("Service$", ""), service))
        end
        table.insert(output, "")
    end
    
    if #methods > 0 or #events > 0 then
        table.insert(output, "-- Script functionality (reconstructed from strings):")
        for _, method in ipairs(methods) do
            if method == "WaitForChild" then
                table.insert(output, "-- WaitForChild calls detected")
            elseif method == "GetChildren" then
                table.insert(output, "-- GetChildren calls detected")
            end
        end
        
        for _, event in ipairs(events) do
            if event == "Connect" then
                table.insert(output, "-- Event connections detected")
            end
        end
        table.insert(output, "")
    end
    
    -- Add all strings as comments for reference
    table.insert(output, "-- All extracted strings:")
    for i, str in ipairs(strings) do
        if str and #str > 0 then
            table.insert(output, string.format('-- [%d] "%s"', i, str))
        end
    end
    
    if #output == 0 then
        table.insert(output, "-- No meaningful patterns found in string data")
        table.insert(output, "-- Raw string count: " .. tostring(#strings))
    end
    
    return output
end

function LuauDecompiler:Decompile(proto, bytecodeInfo, level)
    level = level or 0
    local output = {}
    
    if level == 0 then
        table.insert(output, "-- Universal Luau Decompiler V3")
        table.insert(output, "-- Bytecode Version: " .. tostring(bytecodeInfo.version))
        table.insert(output, "-- String Count: " .. tostring(#bytecodeInfo.strings))
        table.insert(output, "-- Proto Count: " .. tostring(#bytecodeInfo.protos))
        table.insert(output, "")
    end
    
    local indent = string.rep("  ", level)
    
    table.insert(output, indent .. "-- Function (params: " .. tostring(proto.numParams) .. 
                         ", stack: " .. tostring(proto.maxStackSize) .. 
                         ", upvals: " .. tostring(proto.numUpvals) .. 
                         ", vararg: " .. tostring(proto.isVararg) .. ")")
    
    if #proto.instructions > 0 then
        table.insert(output, indent .. "-- Instructions: " .. tostring(#proto.instructions))
        local body = self:DecompileStructured(proto, bytecodeInfo)
        for line in string.gmatch(body, "[^\n]+") do
            table.insert(output, indent .. line)
        end
    else
        table.insert(output, indent .. "-- No instructions found")
    end
    
    table.insert(output, "")
    
    return table.concat(output, "\n")
end

-- Main entry point
function decompilev2(input)
    local t0 = tick and tick() or 0  -- Use tick() if available, otherwise 0
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
    
    print("🚀 Universal Luau Decompiler V3")
    print("📊 Bytecode size: " .. #bytecode .. " bytes")
    
    -- Attempt decompilation
    local success, result = pcall(function()
        local bytecodeInfo = LuauDecompiler:ParseBytecode(bytecode)
        local decompiledCode
        
        if #bytecodeInfo.protos == 0 or not bytecodeInfo.mainProto then
            -- No bytecode protos found, try to reconstruct from strings
            print("⚠️ No bytecode protos found, attempting string reconstruction...")
            local reconstructed = LuauDecompiler:ReconstructFromStrings(bytecodeInfo.strings)
            decompiledCode = table.concat(reconstructed, "\n")
        else
            decompiledCode = LuauDecompiler:Decompile(bytecodeInfo.mainProto, bytecodeInfo, 0)
            
            -- Add remaining protos
            for i = 2, #bytecodeInfo.protos do
                decompiledCode = decompiledCode .. "\n\n-- Proto " .. i .. "\n"
                decompiledCode = decompiledCode .. LuauDecompiler:Decompile(bytecodeInfo.protos[i], bytecodeInfo, 0)
            end
        end
        
        local elapsed = tick and (tick() - t0) or 0
        
        -- Create header without using os.date which might not be available
        local header = "-- Universal Luau Decompiler V3\n"
        if elapsed > 0 then
            header = header .. string.format("-- Time taken: %.6f seconds\n", elapsed)
        end
        header = header .. "-- String count: " .. tostring(#bytecodeInfo.strings) .. "\n"
        header = header .. "-- Proto count: " .. tostring(#bytecodeInfo.protos) .. "\n\n"
        
        decompiledCode = header .. decompiledCode
        
        -- Write to file if writefile is available
        if writefile then
            writefile(outputPath, decompiledCode)
            print("✅ Decompilation saved to: " .. outputPath)
        end
        
        print("✅ Decompilation completed!")
        if elapsed > 0 then
            print(string.format("⏱️ Time: %.6fs", elapsed))
        end
        if bytecodeInfo.mainProto and #bytecodeInfo.mainProto.instructions > 0 then
            print("📏 Instructions processed: " .. tostring(#bytecodeInfo.mainProto.instructions))
        else
            print("📄 String reconstruction mode used")
        end
        
        return decompiledCode
    end)
    
    if not success then
        error("Decompilation failed: " .. tostring(result))
    end
    
    return result
end

-- Set global
_G.decompilev2 = decompilev2

print("🌍 Universal Luau Decompiler V3 Loaded!")
print("💡 Usage: decompilev2(script_or_path)")

return LuauDecompiler
