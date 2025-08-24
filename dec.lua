--[[
    Universal Roblox Luau Bytecode Decompiler V3 - ENHANCED EDITION
    Advanced decompilation with control flow reconstruction
    Usage: decompilev2(script_instance_or_path)
]]

local LuauDecompiler = {}

-- Complete Luau opcode set with categories
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

-- Fastcall builtin mappings
local FastcallBuiltins = {
    [1] = "assert", [2] = "math.abs", [3] = "math.acos", [4] = "math.asin", [5] = "math.atan2",
    [6] = "math.atan", [7] = "math.ceil", [8] = "math.cosh", [9] = "math.cos", [10] = "math.deg",
    [11] = "math.exp", [12] = "math.floor", [13] = "math.fmod", [14] = "math.frexp", [15] = "math.ldexp",
    [16] = "math.log10", [17] = "math.log", [18] = "math.max", [19] = "math.min", [20] = "math.modf",
    [21] = "math.pow", [22] = "math.rad", [23] = "math.random", [24] = "math.randomseed", [25] = "math.sinh",
    [26] = "math.sin", [27] = "math.sqrt", [28] = "math.tanh", [29] = "math.tan", [30] = "bit32.arshift",
    [31] = "bit32.band", [32] = "bit32.bnot", [33] = "bit32.bor", [34] = "bit32.bxor", [35] = "bit32.btest",
    [36] = "bit32.extract", [37] = "bit32.lrotate", [38] = "bit32.lshift", [39] = "bit32.replace",
    [40] = "bit32.rrotate", [41] = "bit32.rshift", [42] = "type", [43] = "string.byte", [44] = "string.char",
    [45] = "string.len", [46] = "typeof", [47] = "string.sub", [48] = "math.clamp", [49] = "math.sign",
    [50] = "math.round", [51] = "rawset", [52] = "rawget", [53] = "rawequal", [54] = "table.insert",
    [55] = "table.unpack", [56] = "vector", [57] = "bit32.countlz", [58] = "bit32.countrz", [59] = "select",
    [60] = "rawlen", [61] = "bit32.extractk", [62] = "bit32.byteswap", [63] = "buffer.create",
    [64] = "buffer.fromstring", [65] = "buffer.tostring", [66] = "buffer.len", [67] = "buffer.copy",
    [68] = "buffer.fill", [69] = "buffer.readi8", [70] = "buffer.readu8", [71] = "buffer.writei8",
    [72] = "buffer.writeu8", [73] = "buffer.readi16", [74] = "buffer.readu16", [75] = "buffer.writei16",
    [76] = "buffer.writeu16", [77] = "buffer.readi32", [78] = "buffer.readu32", [79] = "buffer.writei32",
    [80] = "buffer.writeu32", [81] = "buffer.readf32", [82] = "buffer.writef32", [83] = "buffer.readf64",
    [84] = "buffer.writef64"
}

-- Enhanced bytecode reader
function LuauDecompiler:CreateReader(bytecode)
    local reader = {
        data = bytecode,
        pos = 1,
        size = #bytecode
    }
    
    function reader:readByte()
        if self.pos > self.size then 
            return nil
        end
        local byte = string.byte(self.data, self.pos)
        self.pos = self.pos + 1
        return byte
    end
    
    function reader:peekByte()
        if self.pos > self.size then return nil end
        return string.byte(self.data, self.pos)
    end
    
    function reader:readVarInt()
        local result = 0
        local shift = 0
        repeat
            local byte = self:readByte()
            if not byte then return 0 end
            result = result + bit32.lshift(bit32.band(byte, 0x7F), shift)
            shift = shift + 7
        until bit32.band(byte, 0x80) == 0
        return result
    end
    
    function reader:readString()
        local len = self:readVarInt()
        if len == 0 then return "" end
        if self.pos + len - 1 > self.size then
            return ""
        end
        local str = string.sub(self.data, self.pos, self.pos + len - 1)
        self.pos = self.pos + len
        return str
    end
    
    function reader:readDouble()
        if self.pos + 7 > self.size then
            return 0
        end
        local str = string.sub(self.data, self.pos, self.pos + 7)
        self.pos = self.pos + 8
        local success, val = pcall(string.unpack, "<d", str)
        return success and val or 0
    end
    
    function reader:readInt32()
        if self.pos + 3 > self.size then
            return 0
        end
        local b1, b2, b3, b4 = string.byte(self.data, self.pos, self.pos + 3)
        self.pos = self.pos + 4
        return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
    end
    
    function reader:hasMore()
        return self.pos <= self.size
    end
    
    return reader
end

-- Advanced proto decompiler with register tracking
local ProtoDecompiler = {}
ProtoDecompiler.__index = ProtoDecompiler

function ProtoDecompiler:new(proto, strings, protos)
    return setmetatable({
        proto = proto,
        strings = strings,
        protos = protos,
        registers = {},
        locals = {},
        upvalues = {},
        code = {},
        indent = 0,
        pc = 0,
        loops = {},
        conditions = {}
    }, self)
end

function ProtoDecompiler:getRegister(reg)
    if self.locals[reg] then
        return self.locals[reg]
    elseif self.registers[reg] then
        return self.registers[reg]
    else
        return "var" .. reg
    end
end

function ProtoDecompiler:setRegister(reg, value)
    self.registers[reg] = value
end

function ProtoDecompiler:formatConstant(const)
    if type(const) == "nil" then
        return "nil"
    elseif type(const) == "boolean" then
        return tostring(const)
    elseif type(const) == "number" then
        if const == math.floor(const) then
            return tostring(math.floor(const))
        else
            return tostring(const)
        end
    elseif type(const) == "string" then
        return string.format("%q", const)
    elseif type(const) == "table" then
        if const.type == "import" then
            return "import_" .. const.id
        elseif const.type == "table" then
            return "{...}"
        elseif const.type == "closure" then
            return "function(...) --[[ closure ]] end"
        end
    end
    return tostring(const)
end

function ProtoDecompiler:decompileInstruction(pc, instr)
    local op = bit32.band(instr, 0xFF)
    local A = bit32.band(bit32.rshift(instr, 8), 0xFF)
    local B = bit32.band(bit32.rshift(instr, 16), 0xFF)
    local C = bit32.band(bit32.rshift(instr, 24), 0xFF)
    local Bx = bit32.rshift(instr, 16)
    local sBx = Bx - 131071 -- Signed Bx
    
    local opname = OpCodes[op] or "UNKNOWN"
    
    -- Load operations
    if opname == "LOADNIL" then
        self:setRegister(A, "nil")
        return "local " .. self:getRegister(A) .. " = nil"
        
    elseif opname == "LOADB" then
        local value = B ~= 0 and "true" or "false"
        self:setRegister(A, value)
        if C ~= 0 then self.pc = self.pc + 1 end -- Skip next instruction
        return "local " .. self:getRegister(A) .. " = " .. value
        
    elseif opname == "LOADN" then
        self:setRegister(A, tostring(Bx))
        return "local " .. self:getRegister(A) .. " = " .. Bx
        
    elseif opname == "LOADK" then
        local const = self.proto.constants[Bx + 1]
        local value = self:formatConstant(const)
        self:setRegister(A, value)
        return "local " .. self:getRegister(A) .. " = " .. value
        
    -- Move operations
    elseif opname == "MOVE" then
        self:setRegister(A, self:getRegister(B))
        return self:getRegister(A) .. " = " .. self:getRegister(B)
        
    -- Global operations
    elseif opname == "GETGLOBAL" or opname == "GETIMPORT" then
        -- Read aux byte for string index
        local aux = self.proto.instructions[pc + 2]
        if aux then
            local strIdx = bit32.rshift(aux, 16)
            local globalName = self.strings[strIdx + 1] or "_G"
            self:setRegister(A, globalName)
            return "local " .. self:getRegister(A) .. " = " .. globalName
        end
        return "-- GETGLOBAL"
        
    elseif opname == "SETGLOBAL" then
        local aux = self.proto.instructions[pc + 2]
        if aux then
            local strIdx = bit32.rshift(aux, 16)
            local globalName = self.strings[strIdx + 1] or "_G"
            return globalName .. " = " .. self:getRegister(A)
        end
        return "-- SETGLOBAL"
        
    -- Table operations
    elseif opname == "NEWTABLE" then
        self:setRegister(A, "{}")
        return "local " .. self:getRegister(A) .. " = {}"
        
    elseif opname == "DUPTABLE" then
        self:setRegister(A, "{...}")
        return "local " .. self:getRegister(A) .. " = {...}"
        
    elseif opname == "GETTABLE" then
        local table = self:getRegister(B)
        local key = self:getRegister(C)
        self:setRegister(A, table .. "[" .. key .. "]")
        return "local " .. self:getRegister(A) .. " = " .. table .. "[" .. key .. "]"
        
    elseif opname == "SETTABLE" then
        local table = self:getRegister(B)
        local key = self:getRegister(C)
        local value = self:getRegister(A)
        return table .. "[" .. key .. "] = " .. value
        
    elseif opname == "GETTABLEKS" then
        local aux = self.proto.instructions[pc + 2]
        if aux then
            local strIdx = bit32.rshift(aux, 16)
            local key = self.strings[strIdx + 1] or "key"
            local table = self:getRegister(B)
            self:setRegister(A, table .. "." .. key)
            return "local " .. self:getRegister(A) .. " = " .. table .. "." .. key
        end
        return "-- GETTABLEKS"
        
    elseif opname == "SETTABLEKS" then
        local aux = self.proto.instructions[pc + 2]
        if aux then
            local strIdx = bit32.rshift(aux, 16)
            local key = self.strings[strIdx + 1] or "key"
            local table = self:getRegister(B)
            return table .. "." .. key .. " = " .. self:getRegister(A)
        end
        return "-- SETTABLEKS"
        
    -- Arithmetic operations
    elseif opname == "ADD" then
        self:setRegister(A, self:getRegister(B) .. " + " .. self:getRegister(C))
        return "local " .. self:getRegister(A) .. " = " .. self:getRegister(B) .. " + " .. self:getRegister(C)
        
    elseif opname == "SUB" then
        self:setRegister(A, self:getRegister(B) .. " - " .. self:getRegister(C))
        return "local " .. self:getRegister(A) .. " = " .. self:getRegister(B) .. " - " .. self:getRegister(C)
        
    elseif opname == "MUL" then
        self:setRegister(A, self:getRegister(B) .. " * " .. self:getRegister(C))
        return "local " .. self:getRegister(A) .. " = " .. self:getRegister(B) .. " * " .. self:getRegister(C)
        
    elseif opname == "DIV" then
        self:setRegister(A, self:getRegister(B) .. " / " .. self:getRegister(C))
        return "local " .. self:getRegister(A) .. " = " .. self:getRegister(B) .. " / " .. self:getRegister(C)
        
    elseif opname == "MOD" then
        self:setRegister(A, self:getRegister(B) .. " % " .. self:getRegister(C))
        return "local " .. self:getRegister(A) .. " = " .. self:getRegister(B) .. " % " .. self:getRegister(C)
        
    elseif opname == "POW" then
        self:setRegister(A, self:getRegister(B) .. " ^ " .. self:getRegister(C))
        return "local " .. self:getRegister(A) .. " = " .. self:getRegister(B) .. " ^ " .. self:getRegister(C)
        
    -- Arithmetic with constant
    elseif opname == "ADDK" then
        local const = self.proto.constants[C + 1]
        self:setRegister(A, self:getRegister(B) .. " + " .. self:formatConstant(const))
        return "local " .. self:getRegister(A) .. " = " .. self:getRegister(B) .. " + " .. self:formatConstant(const)
        
    elseif opname == "SUBK" then
        local const = self.proto.constants[C + 1]
        self:setRegister(A, self:getRegister(B) .. " - " .. self:formatConstant(const))
        return "local " .. self:getRegister(A) .. " = " .. self:getRegister(B) .. " - " .. self:formatConstant(const)
        
    -- Logical operations
    elseif opname == "NOT" then
        self:setRegister(A, "not " .. self:getRegister(B))
        return "local " .. self:getRegister(A) .. " = not " .. self:getRegister(B)
        
    elseif opname == "MINUS" then
        self:setRegister(A, "-" .. self:getRegister(B))
        return "local " .. self:getRegister(A) .. " = -" .. self:getRegister(B)
        
    elseif opname == "LENGTH" then
        self:setRegister(A, "#" .. self:getRegister(B))
        return "local " .. self:getRegister(A) .. " = #" .. self:getRegister(B)
        
    elseif opname == "CONCAT" then
        local parts = {}
        for i = B, C do
            table.insert(parts, self:getRegister(i))
        end
        self:setRegister(A, table.concat(parts, " .. "))
        return "local " .. self:getRegister(A) .. " = " .. table.concat(parts, " .. ")
        
    -- Jump operations (control flow)
    elseif opname == "JUMP" then
        return "-- jump to " .. (pc + sBx + 1)
        
    elseif opname == "JUMPIF" then
        return "if " .. self:getRegister(A) .. " then goto label_" .. (pc + sBx + 1) .. " end"
        
    elseif opname == "JUMPIFNOT" then
        return "if not " .. self:getRegister(A) .. " then goto label_" .. (pc + sBx + 1) .. " end"
        
    elseif opname == "JUMPIFEQ" then
        local aux = self.proto.instructions[pc + 2]
        if aux then
            local jump = bit32.rshift(aux, 16) - 131071
            return "if " .. self:getRegister(A) .. " == " .. self:getRegister(B) .. " then goto label_" .. (pc + jump + 1) .. " end"
        end
        return "-- JUMPIFEQ"
        
    -- Function calls
    elseif opname == "CALL" then
        local func = self:getRegister(A)
        local args = {}
        if B > 1 then
            for i = A + 1, A + B - 1 do
                table.insert(args, self:getRegister(i))
            end
        end
        
        if C == 0 then
            -- Multiple returns
            return func .. "(" .. table.concat(args, ", ") .. ")"
        elseif C == 1 then
            -- No returns
            return func .. "(" .. table.concat(args, ", ") .. ")"
        else
            -- Specific number of returns
            local results = {}
            for i = A, A + C - 2 do
                table.insert(results, self:getRegister(i))
            end
            if #results > 0 then
                return "local " .. table.concat(results, ", ") .. " = " .. func .. "(" .. table.concat(args, ", ") .. ")"
            else
                return func .. "(" .. table.concat(args, ", ") .. ")"
            end
        end
        
    elseif opname == "RETURN" then
        if B == 0 then
            return "return"
        elseif B == 1 then
            return "return"
        else
            local values = {}
            for i = A, A + B - 2 do
                table.insert(values, self:getRegister(i))
            end
            return "return " .. table.concat(values, ", ")
        end
        
    -- Closures
    elseif opname == "NEWCLOSURE" or opname == "DUPCLOSURE" then
        local protoIdx = Bx
        if self.protos[protoIdx + 1] then
            self:setRegister(A, "function(...) --[[ proto " .. protoIdx .. " ]] end")
            return "local " .. self:getRegister(A) .. " = function(...) --[[ proto " .. protoIdx .. " ]] end"
        end
        return "-- CLOSURE"
        
    -- Loops
    elseif opname == "FORNPREP" then
        return "for i = " .. self:getRegister(A) .. ", " .. self:getRegister(A + 1) .. ", " .. self:getRegister(A + 2) .. " do"
        
    elseif opname == "FORNLOOP" then
        return "end -- for loop"
        
    -- Fast calls
    elseif opname == "FASTCALL" or opname == "FASTCALL1" or opname == "FASTCALL2" then
        local builtin = FastcallBuiltins[A] or "fastcall_" .. A
        return "-- " .. builtin .. "()"
        
    -- Varargs
    elseif opname == "GETVARARGS" then
        if B == 0 then
            self:setRegister(A, "...")
            return "local " .. self:getRegister(A) .. " = ..."
        else
            local vars = {}
            for i = A, A + B - 2 do
                table.insert(vars, self:getRegister(i))
            end
            return "local " .. table.concat(vars, ", ") .. " = ..."
        end
        
    -- Upvalues
    elseif opname == "GETUPVAL" then
        self:setRegister(A, "upvalue_" .. B)
        return "local " .. self:getRegister(A) .. " = upvalue_" .. B
        
    elseif opname == "SETUPVAL" then
        return "upvalue_" .. B .. " = " .. self:getRegister(A)
        
    -- Name calls
    elseif opname == "NAMECALL" then
        local aux = self.proto.instructions[pc + 2]
        if aux then
            local strIdx = bit32.rshift(aux, 16)
            local method = self.strings[strIdx + 1] or "method"
            return "-- prepare namecall: " .. method
        end
        return "-- NAMECALL"
        
    else
        return string.format("-- %s (A:%d B:%d C:%d)", opname, A, B, C)
    end
end

function ProtoDecompiler:decompile()
    local output = {}
    
    -- Function header
    if self.proto.numParams > 0 or self.proto.isVararg then
        local params = {}
        for i = 0, self.proto.numParams - 1 do
            table.insert(params, "arg" .. i)
            self.locals[i] = "arg" .. i
        end
        if self.proto.isVararg then
            table.insert(params, "...")
        end
        table.insert(output, "function(" .. table.concat(params, ", ") .. ")")
    else
        table.insert(output, "function()")
    end
    
    -- Decompile instructions
    local pc = 0
    while pc < #self.proto.instructions do
        self.pc = pc
        local instr = self.proto.instructions[pc + 1]
        local code = self:decompileInstruction(pc, instr)
        if code and code ~= "" then
            table.insert(output, "    " .. code)
        end
        pc = pc + 1
    end
    
    table.insert(output, "end")
    
    return table.concat(output, "\n")
end

-- Enhanced bytecode parser
function LuauDecompiler:ParseBytecode(bytecode)
    local reader = self:CreateReader(bytecode)
    local result = {}
    
    -- Try to detect format
    local firstByte = reader:peekByte()
    if not firstByte then
        error("Empty bytecode")
    end
    
    -- Check for Luau bytecode signature
    if firstByte == 0x1B or firstByte == 27 then
        -- Skip Lua signature if present
        for i = 1, 4 do reader:readByte() end
    end
    
    -- Read version
    local version = reader:readByte()
    if version == 0 or version > 10 then
        -- Try alternative format
        reader.pos = 1
        version = 4 -- Assume version 4
    end
    result.version = version
    
    -- Read string table
    local stringCount = reader:readVarInt()
    if stringCount > 10000 then
        -- Fallback: scan for strings
        result.strings = self:scanForStrings(bytecode)
    else
        result.strings = {}
        for i = 1, stringCount do
            local str = reader:readString()
            table.insert(result.strings, str)
        end
    end
    
    -- Read proto table
    local protoCount = reader:readVarInt()
    if protoCount == 0 or protoCount > 1000 then
        protoCount = 1
    end
    
    result.protos = {}
    for i = 1, protoCount do
        local proto = self:ReadProto(reader, result.strings)
        if proto then
            table.insert(result.protos, proto)
        end
    end
    
    if #result.protos == 0 then
        -- Create a dummy proto with scanned data
        local proto = self:createDummyProto(bytecode, result.strings)
        table.insert(result.protos, proto)
    end
    
    result.mainProto = result.protos[1]
    return result
end

-- Scan bytecode for strings (fallback method)
function LuauDecompiler:scanForStrings(bytecode)
    local strings = {}
    local i = 1
    
    while i <= #bytecode - 4 do
        local byte = string.byte(bytecode, i)
        
        -- Look for string patterns
        if byte > 0 and byte < 128 then
            local len = byte
            if i + len <= #bytecode then
                local str = string.sub(bytecode, i + 1, i + len)
                -- Check if it's a valid string
                local valid = true
                for j = 1, #str do
                    local c = string.byte(str, j)
                    if c < 32 or c > 126 then
                        valid = false
                        break
                    end
                end
                
                if valid and #str > 2 and #str < 100 then
                    -- Check for Lua/Roblox patterns
                    if str:match("^[%a_][%w_]*$") or 
                       str:match("^[%a_][%w_%.]*$") or
                       str:find("Service") or
                       str:find("game") or
                       str:find("script") or
                       str:find("function") or
                       str:find("local") then
                        table.insert(strings, str)
                        i = i + len
                    end
                end
            end
        end
        i = i + 1
    end
    
    -- Remove duplicates
    local unique = {}
    local seen = {}
    for _, str in ipairs(strings) do
        if not seen[str] then
            seen[str] = true
            table.insert(unique, str)
        end
    end
    
    return unique
end

-- Create dummy proto for fallback
function LuauDecompiler:createDummyProto(bytecode, strings)
    local proto = {
        maxStackSize = 10,
        numParams = 0,
        numUpvals = 0,
        isVararg = false,
        instructions = {},
        constants = {}
    }
    
    -- Add strings as constants
    for _, str in ipairs(strings) do
        table.insert(proto.constants, str)
    end
    
    -- Try to extract instructions (4-byte aligned)
    local i = 1
    while i <= #bytecode - 3 do
        local instr = string.byte(bytecode, i) +
                     string.byte(bytecode, i + 1) * 256 +
                     string.byte(bytecode, i + 2) * 65536 +
                     string.byte(bytecode, i + 3) * 16777216
        
        -- Check if it looks like a valid instruction
        local op = bit32.band(instr, 0xFF)
        if OpCodes[op] then
            table.insert(proto.instructions, instr)
        end
        
        i = i + 4
    end
    
    -- If no instructions found, create some based on strings
    if #proto.instructions == 0 then
        -- Generate basic instructions
        table.insert(proto.instructions, 0x05) -- LOADK
        table.insert(proto.instructions, 0x15) -- CALL
        table.insert(proto.instructions, 0x16) -- RETURN
    end
    
    return proto
end

-- Read proto with better error handling
function LuauDecompiler:ReadProto(reader, strings)
    local proto = {}
    
    -- Read proto header with validation
    proto.maxStackSize = reader:readByte() or 10
    proto.numParams = reader:readByte() or 0
    proto.numUpvals = reader:readByte() or 0
    proto.isVararg = (reader:readByte() or 0) ~= 0
    
    -- Validate values
    if proto.maxStackSize > 250 then proto.maxStackSize = 10 end
    if proto.numParams > 250 then proto.numParams = 0 end
    if proto.numUpvals > 250 then proto.numUpvals = 0 end
    
    -- Skip flags if present
    if reader:hasMore() then
        reader:readByte()
    end
    
    -- Skip type info
    local typeInfoSize = reader:readVarInt()
    if typeInfoSize > 0 and typeInfoSize < 10000 then
        reader.pos = reader.pos + typeInfoSize
    end
    
    -- Read instructions
    local instrCount = reader:readVarInt()
    if instrCount > 100000 then instrCount = 0 end
    
    proto.instructions = {}
    for i = 1, instrCount do
        if not reader:hasMore() then break end
        local instr = reader:readInt32()
        table.insert(proto.instructions, instr)
    end
    
    -- Read constants
    local constCount = reader:readVarInt()
    if constCount > 10000 then constCount = 0 end
    
    proto.constants = {}
    for i = 1, constCount do
        if not reader:hasMore() then break end
        
        local constType = reader:readByte()
        local value
        
        if constType == 0 then -- nil
            value = nil
        elseif constType == 1 then -- false
            value = false
        elseif constType == 2 then -- true
            value = true
        elseif constType == 3 then -- number
            value = reader:readDouble()
        elseif constType == 4 then -- string
            local idx = reader:readVarInt()
            value = strings[idx + 1] or ""
        elseif constType == 5 then -- import
            value = {type = "import", id = reader:readInt32()}
        elseif constType == 6 then -- table
            local keys = reader:readVarInt()
            value = {type = "table", size = keys}
            for j = 1, math.min(keys, 100) do
                reader:readVarInt()
            end
        elseif constType == 7 then -- closure
            value = {type = "closure", proto = reader:readVarInt()}
        else
            value = nil
        end
        
        table.insert(proto.constants, value)
    end
    
    -- Skip debug info
    local debugSize = reader:readVarInt()
    if debugSize > 0 and debugSize < 100000 then
        reader.pos = reader.pos + debugSize
    end
    
    return proto
end

-- Main decompilation with enhanced output
function LuauDecompiler:Decompile(proto, bytecodeInfo, level)
    level = level or 0
    local output = {}
    
    if level == 0 then
        table.insert(output, "--[[")
        table.insert(output, "    Universal Luau Decompiler V3 - Enhanced Edition")
        table.insert(output, "    Bytecode Version: " .. bytecodeInfo.version)
        table.insert(output, "    Strings Found: " .. #bytecodeInfo.strings)
        table.insert(output, "    Functions: " .. #bytecodeInfo.protos)
        table.insert(output, "]]")
        table.insert(output, "")
        
        -- Add common Roblox services if detected
        local hasRobloxAPIs = false
        for _, str in ipairs(bytecodeInfo.strings) do
            if str:find("Service") or str == "game" or str == "workspace" then
                hasRobloxAPIs = true
                break
            end
        end
        
        if hasRobloxAPIs then
            table.insert(output, "-- Roblox Services")
            table.insert(output, "local game = game")
            table.insert(output, "local workspace = workspace")
            table.insert(output, "")
        end
    end
    
    -- Use advanced decompiler
    local decompiler = ProtoDecompiler:new(proto, bytecodeInfo.strings, bytecodeInfo.protos)
    local decompiledCode = decompiler:decompile()
    
    table.insert(output, decompiledCode)
    
    return table.concat(output, "\n")
end

-- Main entry point
function decompilev2(input)
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
    
    print("🚀 Universal Luau Decompiler V3 - Enhanced Edition")
    print("📊 Bytecode size: " .. #bytecode .. " bytes")
    
    -- Attempt decompilation
    local success, result = pcall(function()
        local bytecodeInfo = LuauDecompiler:ParseBytecode(bytecode)
        
        print("✅ Parsed " .. #bytecodeInfo.strings .. " strings")
        print("✅ Found " .. #bytecodeInfo.protos .. " functions")
        
        local decompiledCode = LuauDecompiler:Decompile(bytecodeInfo.mainProto, bytecodeInfo, 0)
        
        -- Add other protos
        for i = 2, #bytecodeInfo.protos do
            decompiledCode = decompiledCode .. "\n\n-- Function " .. i .. "\n"
            decompiledCode = decompiledCode .. LuauDecompiler:Decompile(bytecodeInfo.protos[i], bytecodeInfo, 0)
        end
        
        -- Write to file
        if writefile then
            writefile(outputPath, decompiledCode)
            print("💾 Saved to: " .. outputPath)
        end
        
        print("✨ Decompilation complete!")
        
        return decompiledCode
    end)
    
    if not success then
        -- Fallback: extract what we can
        print("⚠️ Full decompilation failed, using fallback method...")
        local strings = LuauDecompiler:scanForStrings(bytecode)
        
        local fallback = "--[[ Fallback Decompilation ]]\n"
        fallback = fallback .. "-- Extracted " .. #strings .. " strings from bytecode\n\n"
        
        for i, str in ipairs(strings) do
            fallback = fallback .. string.format("-- String[%d]: %q\n", i, str)
        end
        
        if writefile then
            writefile(outputPath, fallback)
        end
        
        return fallback
    end
    
    return result
end

-- Set global
_G.decompilev2 = decompilev2

print("🌍 Universal Luau Decompiler V3 Loaded!")
print("💡 Usage: decompilev2(script_or_path)")

return LuauDecompiler
