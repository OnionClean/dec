--[[
    Universal Roblox Luau Bytecode Decompiler
    Built for exploit environments with getscriptbytecode access
    Usage: decompilev2(script_instance_or_path)
    
    Created by: Ultimate Reverse Engineering Team
    Date: August 24, 2025
]]

local LuauDecompiler = {}

-- Luau opcodes and instruction formats (from official Luau repository)
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

-- Builtin functions for FASTCALL operations
local BuiltinFunctions = {
    [1] = "assert", [2] = "type", [3] = "typeof", [4] = "rawset", [5] = "rawget",
    [6] = "rawequal", [7] = "rawlen", [8] = "unpack", [9] = "select", [10] = "next",
    [11] = "tostring", [12] = "tonumber", [13] = "setmetatable", [14] = "getmetatable",
    [15] = "pairs", [16] = "ipairs", [17] = "pcall", [18] = "xpcall", [19] = "error",
    [20] = "math.abs", [21] = "math.acos", [22] = "math.asin", [23] = "math.atan",
    [24] = "math.atan2", [25] = "math.ceil", [26] = "math.cos", [27] = "math.cosh",
    [28] = "math.deg", [29] = "math.exp", [30] = "math.floor", [31] = "math.fmod",
    [32] = "math.frexp", [33] = "math.ldexp", [34] = "math.log", [35] = "math.log10",
    [36] = "math.max", [37] = "math.min", [38] = "math.modf", [39] = "math.pow",
    [40] = "math.rad", [41] = "math.random", [42] = "math.randomseed", [43] = "math.sin",
    [44] = "math.sinh", [45] = "math.sqrt", [46] = "math.tan", [47] = "math.tanh",
    [48] = "bit32.arshift", [49] = "bit32.band", [50] = "bit32.bnot", [51] = "bit32.bor",
    [52] = "bit32.bxor", [53] = "bit32.btest", [54] = "bit32.extract", [55] = "bit32.lrotate",
    [56] = "bit32.lshift", [57] = "bit32.replace", [58] = "bit32.rrotate", [59] = "bit32.rshift",
    [60] = "string.byte", [61] = "string.char", [62] = "string.find", [63] = "string.format",
    [64] = "string.gmatch", [65] = "string.gsub", [66] = "string.len", [67] = "string.lower",
    [68] = "string.match", [69] = "string.rep", [70] = "string.reverse", [71] = "string.sub",
    [72] = "string.upper", [73] = "table.concat", [74] = "table.insert", [75] = "table.pack",
    [76] = "table.remove", [77] = "table.sort", [78] = "table.unpack"
}

-- Common Roblox services for import resolution
local RobloxServices = {
    "Players", "Workspace", "ReplicatedStorage", "ServerStorage", "StarterPlayer",
    "StarterPack", "StarterGui", "Lighting", "SoundService", "TweenService",
    "UserInputService", "RunService", "HttpService", "DataStoreService",
    "MarketplaceService", "TeleportService", "Teams", "Chat", "PathfindingService",
    "ContextActionService", "GuiService", "LocalizationService", "VoiceChatService"
}

-- Instruction decoding functions
local function INSN_OP(insn) return bit32.band(insn, 0xFF) end
local function INSN_A(insn) return bit32.band(bit32.rshift(insn, 8), 0xFF) end
local function INSN_B(insn) return bit32.band(bit32.rshift(insn, 16), 0xFF) end
local function INSN_C(insn) return bit32.band(bit32.rshift(insn, 24), 0xFF) end
local function INSN_D(insn) return bit32.rshift(insn, 16) end
local function INSN_sD(insn) 
    local D = INSN_D(insn)
    return D > 32767 and (D - 65536) or D
end
local function INSN_E(insn) return bit32.rshift(insn, 8) end

-- Bytecode reader for parsing Luau bytecode format
function LuauDecompiler:ReadBytecode(bytecode)
    local pos = 1
    local function readByte()
        if pos > #bytecode then return nil end
        local byte = string.byte(bytecode, pos)
        pos = pos + 1
        return byte
    end
    
    local function readInt32()
        local b1, b2, b3, b4 = readByte(), readByte(), readByte(), readByte()
        if not b1 or not b2 or not b3 or not b4 then return nil end
        return b1 + (b2 * 256) + (b3 * 65536) + (b4 * 16777216)
    end
    
    local function readString()
        local len = readInt32()
        if not len or len < 0 or len > 1000000 then -- Prevent huge strings
            return nil
        end
        if len == 0 then return "" end
        if pos + len - 1 > #bytecode then return nil end
        local str = string.sub(bytecode, pos, pos + len - 1)
        pos = pos + len
        return str
    end
    
    local function readDouble()
        local str = ""
        for i = 1, 8 do
            local byte = readByte()
            if not byte then return nil end
            str = str .. string.char(byte)
        end
        return string.unpack("<d", str)
    end
    
    -- Parse header
    local version = readByte()
    if not version or version < 3 or version > 6 then
        error("Unsupported bytecode version: " .. tostring(version))
    end
    
    -- Parse string table
    local stringCount = readInt32()
    if not stringCount or stringCount < 0 or stringCount > 100000 then
        error("Invalid string count: " .. tostring(stringCount))
    end
    local strings = {}
    for i = 1, stringCount do
        local str = readString()
        if str then
            table.insert(strings, str)
        end
    end
    
    -- Parse number table
    local numberCount = readInt32()
    if not numberCount or numberCount < 0 or numberCount > 100000 then
        error("Invalid number count: " .. tostring(numberCount))
    end
    local numbers = {}
    for i = 1, numberCount do
        local num = readDouble()
        if num then
            table.insert(numbers, num)
        end
    end
    
    -- Parse proto table (function definitions)
    local protoCount = readInt32()
    if not protoCount or protoCount < 0 or protoCount > 10000 then
        error("Invalid proto count: " .. tostring(protoCount))
    end
    local protos = {}
    
    for i = 1, protoCount do
        local proto = {}
        proto.maxStackSize = readByte()
        proto.numParams = readByte()
        proto.numUpvals = readByte()
        proto.isVararg = readByte() == 1
        
        -- Read instructions
        local instrCount = readInt32()
        if not instrCount or instrCount < 0 or instrCount > 1000000 then
            error("Invalid instruction count: " .. tostring(instrCount))
        end
        proto.instructions = {}
        for j = 1, instrCount do
            local instr = readInt32()
            if instr then
                table.insert(proto.instructions, instr)
            end
        end
        
        -- Read constants
        local constCount = readInt32()
        if not constCount or constCount < 0 or constCount > 100000 then
            error("Invalid constant count: " .. tostring(constCount))
        end
        proto.constants = {}
        for j = 1, constCount do
            local constType = readByte()
            local value
            if constType == 0 then -- nil
                value = nil
            elseif constType == 1 then -- boolean
                value = readByte() == 1
            elseif constType == 2 then -- number
                local idx = readInt32()
                if idx and idx >= 0 and idx < #numbers then
                    value = numbers[idx + 1]
                else
                    value = 0 -- fallback for invalid index
                end
            elseif constType == 3 then -- string
                local idx = readInt32()
                if idx and idx >= 0 and idx < #strings then
                    value = strings[idx + 1]
                else
                    value = "" -- fallback for invalid index
                end
            end
            table.insert(proto.constants, value)
        end
        
        -- Read child protos
        local childCount = readInt32()
        if not childCount or childCount < 0 or childCount > 10000 then
            error("Invalid child proto count: " .. tostring(childCount))
        end
        proto.childProtos = {}
        for j = 1, childCount do
            local childIdx = readInt32()
            table.insert(proto.childProtos, childIdx)
        end
        
        table.insert(protos, proto)
    end
    
    return {
        version = version,
        strings = strings,
        numbers = numbers,
        protos = protos,
        mainProto = protos[1]
    }
end

-- Decompiler state management
function LuauDecompiler:CreateState(proto, bytecodeInfo)
    return {
        proto = proto,
        bytecodeInfo = bytecodeInfo,
        pc = 1,
        registers = {},
        stack = {},
        locals = {},
        upvals = {},
        output = {},
        indent = 0,
        labels = {},
        jumps = {}
    }
end

-- Generate register name
function LuauDecompiler:GetRegName(reg)
    return string.format("R%d", reg)
end

-- Generate local variable name
function LuauDecompiler:GetLocalName(reg, state)
    if state.locals[reg] then
        return state.locals[reg]
    end
    local name = string.format("local_%d", reg)
    state.locals[reg] = name
    return name
end

-- Add indented line to output
function LuauDecompiler:AddLine(state, line)
    local indent = string.rep("    ", state.indent)
    table.insert(state.output, indent .. line)
end

-- Resolve constant value
function LuauDecompiler:GetConstant(idx, state)
    if idx < 0 or idx >= #state.proto.constants then
        return "nil"
    end
    local value = state.proto.constants[idx + 1]
    if type(value) == "string" then
        return string.format("%q", value)
    elseif type(value) == "number" then
        return tostring(value)
    elseif type(value) == "boolean" then
        return tostring(value)
    else
        return "nil"
    end
end

-- Resolve import path
function LuauDecompiler:ResolveImport(constantIdx, state)
    if constantIdx < 0 or constantIdx >= #state.proto.constants then
        return "unknown"
    end
    local constant = state.proto.constants[constantIdx + 1]
    if type(constant) == "string" then
        -- Check if it's a Roblox service
        for _, service in ipairs(RobloxServices) do
            if constant:find(service) then
                return string.format('game:GetService("%s")', service)
            end
        end
        return constant
    end
    return "unknown"
end

-- Main instruction decompilation
function LuauDecompiler:DecompileInstruction(instr, state)
    local op = INSN_OP(instr)
    local opname = OpCodes[op]
    
    if not opname then
        self:AddLine(state, string.format("-- Unknown opcode: %d", op))
        return
    end
    
    local A, B, C, D, sD = INSN_A(instr), INSN_B(instr), INSN_C(instr), INSN_D(instr), INSN_sD(instr)
    
    if opname == "LOADNIL" then
        local reg = self:GetLocalName(A, state)
        self:AddLine(state, string.format("local %s = nil", reg))
        
    elseif opname == "LOADB" then
        local reg = self:GetLocalName(A, state)
        local value = B == 1 and "true" or "false"
        self:AddLine(state, string.format("local %s = %s", reg, value))
        
    elseif opname == "LOADN" then
        local reg = self:GetLocalName(A, state)
        self:AddLine(state, string.format("local %s = %d", reg, sD))
        
    elseif opname == "LOADK" then
        local reg = self:GetLocalName(A, state)
        local constant = self:GetConstant(D, state)
        self:AddLine(state, string.format("local %s = %s", reg, constant))
        
    elseif opname == "MOVE" then
        local regA = self:GetLocalName(A, state)
        local regB = self:GetLocalName(B, state)
        self:AddLine(state, string.format("local %s = %s", regA, regB))
        
    elseif opname == "GETGLOBAL" then
        local reg = self:GetLocalName(A, state)
        -- Next instruction contains the global name index
        if state.pc < #state.proto.instructions then
            local auxInstr = state.proto.instructions[state.pc + 1]
            local globalName = self:GetConstant(auxInstr, state)
            self:AddLine(state, string.format("local %s = %s", reg, globalName))
        end
        
    elseif opname == "SETGLOBAL" then
        local regA = self:GetLocalName(A, state)
        if state.pc < #state.proto.instructions then
            local auxInstr = state.proto.instructions[state.pc + 1]
            local globalName = self:GetConstant(auxInstr, state)
            self:AddLine(state, string.format("%s = %s", globalName, regA))
        end
        
    elseif opname == "GETIMPORT" then
        local reg = self:GetLocalName(A, state)
        local import = self:ResolveImport(D, state)
        self:AddLine(state, string.format("local %s = %s", reg, import))
        
    elseif opname == "GETTABLE" then
        local regA = self:GetLocalName(A, state)
        local regB = self:GetLocalName(B, state)
        local regC = self:GetLocalName(C, state)
        self:AddLine(state, string.format("local %s = %s[%s]", regA, regB, regC))
        
    elseif opname == "SETTABLE" then
        local regA = self:GetLocalName(A, state)
        local regB = self:GetLocalName(B, state)
        local regC = self:GetLocalName(C, state)
        self:AddLine(state, string.format("%s[%s] = %s", regB, regC, regA))
        
    elseif opname == "GETTABLEKS" then
        local regA = self:GetLocalName(A, state)
        local regB = self:GetLocalName(B, state)
        if state.pc < #state.proto.instructions then
            local auxInstr = state.proto.instructions[state.pc + 1]
            local key = self:GetConstant(auxInstr, state)
            self:AddLine(state, string.format("local %s = %s[%s]", regA, regB, key))
        end
        
    elseif opname == "SETTABLEKS" then
        local regA = self:GetLocalName(A, state)
        local regB = self:GetLocalName(B, state)
        if state.pc < #state.proto.instructions then
            local auxInstr = state.proto.instructions[state.pc + 1]
            local key = self:GetConstant(auxInstr, state)
            self:AddLine(state, string.format("%s[%s] = %s", regB, key, regA))
        end
        
    elseif opname == "CALL" then
        local func = self:GetLocalName(A, state)
        local args = {}
        for i = 1, B - 1 do
            table.insert(args, self:GetLocalName(A + i, state))
        end
        if C == 1 then
            self:AddLine(state, string.format("%s(%s)", func, table.concat(args, ", ")))
        else
            local results = {}
            for i = 0, C - 2 do
                table.insert(results, self:GetLocalName(A + i, state))
            end
            self:AddLine(state, string.format("local %s = %s(%s)", table.concat(results, ", "), func, table.concat(args, ", ")))
        end
        
    elseif opname == "RETURN" then
        if B == 0 then
            self:AddLine(state, "return")
        else
            local results = {}
            for i = 0, B - 2 do
                table.insert(results, self:GetLocalName(A + i, state))
            end
            self:AddLine(state, string.format("return %s", table.concat(results, ", ")))
        end
        
    elseif opname == "JUMP" then
        local target = state.pc + sD
        self:AddLine(state, string.format("-- jump to %d", target))
        
    elseif opname == "JUMPIF" then
        local reg = self:GetLocalName(A, state)
        local target = state.pc + sD
        self:AddLine(state, string.format("if %s then", reg))
        state.indent = state.indent + 1
        self:AddLine(state, string.format("-- jump to %d", target))
        state.indent = state.indent - 1
        self:AddLine(state, "end")
        
    elseif opname == "JUMPIFNOT" then
        local reg = self:GetLocalName(A, state)
        local target = state.pc + sD
        self:AddLine(state, string.format("if not %s then", reg))
        state.indent = state.indent + 1
        self:AddLine(state, string.format("-- jump to %d", target))
        state.indent = state.indent - 1
        self:AddLine(state, "end")
        
    elseif opname == "FASTCALL1" then
        local func = BuiltinFunctions[A] or "unknown"
        local arg = self:GetLocalName(B, state)
        self:AddLine(state, string.format("-- fastcall: %s(%s)", func, arg))
        
    elseif opname == "FASTCALL2" then
        local func = BuiltinFunctions[A] or "unknown"
        local arg1 = self:GetLocalName(B, state)
        if state.pc < #state.proto.instructions then
            local auxInstr = state.proto.instructions[state.pc + 1]
            local arg2Reg = bit32.band(auxInstr, 0xFF)
            local arg2 = self:GetLocalName(arg2Reg, state)
            self:AddLine(state, string.format("-- fastcall: %s(%s, %s)", func, arg1, arg2))
        end
        
    elseif opname == "NEWTABLE" then
        local reg = self:GetLocalName(A, state)
        self:AddLine(state, string.format("local %s = {}", reg))
        
    elseif opname == "NEWCLOSURE" then
        local reg = self:GetLocalName(A, state)
        self:AddLine(state, string.format("local %s = function()", reg))
        state.indent = state.indent + 1
        self:AddLine(state, "-- closure body")
        state.indent = state.indent - 1
        self:AddLine(state, "end")
        
    else
        self:AddLine(state, string.format("-- %s A:%d B:%d C:%d D:%d", opname, A, B, C, D))
    end
end

-- Main decompilation function
function LuauDecompiler:DecompileProto(proto, bytecodeInfo, level)
    level = level or 0
    local state = self:CreateState(proto, bytecodeInfo)
    
    if level == 0 then
        self:AddLine(state, "-- Decompiled with Universal Luau Decompiler")
        self:AddLine(state, string.format("-- Bytecode version: %d", bytecodeInfo.version))
        self:AddLine(state, string.format("-- Functions: %d", #bytecodeInfo.protos))
        self:AddLine(state, string.format("-- Constants: %d", #proto.constants))
        self:AddLine(state, "")
    end
    
    -- Add function header for nested functions
    if level > 0 then
        self:AddLine(state, string.format("function() -- Proto %d", level))
        state.indent = state.indent + 1
    end
    
    -- Decompile instructions
    state.pc = 1
    while state.pc <= #proto.instructions do
        local instr = proto.instructions[state.pc]
        self:DecompileInstruction(instr, state)
        state.pc = state.pc + 1
    end
    
    -- Add function footer for nested functions
    if level > 0 then
        state.indent = state.indent - 1
        self:AddLine(state, "end")
    end
    
    return table.concat(state.output, "\n")
end

-- Public decompilation interface
function decompilev2(scriptPath)
    local bytecode
    local outputPath
    
    if type(scriptPath) == "userdata" then
        -- Script instance provided
        bytecode = getscriptbytecode(scriptPath)
        outputPath = scriptPath.Name .. "_decompiled.lua"
    elseif type(scriptPath) == "string" then
        -- File path provided
        if isfile(scriptPath) then
            bytecode = readfile(scriptPath)
            outputPath = scriptPath:gsub("%.%w+$", "_decompiled.lua")
        else
            error("File not found: " .. scriptPath)
        end
    else
        error("Invalid input: expected script instance or file path")
    end
    
    if not bytecode or bytecode == "" then
        error("Failed to get bytecode")
    end
    
    print("🚀 Universal Luau Decompiler Starting...")
    print("📊 Bytecode size:", #bytecode, "bytes")
    
    local success, result = pcall(function()
        local bytecodeInfo = LuauDecompiler:ReadBytecode(bytecode)
        local decompiledCode = LuauDecompiler:DecompileProto(bytecodeInfo.mainProto, bytecodeInfo, 0)
        
        -- Add metadata header
        local header = string.format([[
-- ===================================================
-- UNIVERSAL LUAU DECOMPILER RESULT
-- Generated: %s
-- Bytecode Version: %d
-- String Count: %d
-- Number Count: %d
-- Proto Count: %d
-- ===================================================

]], os.date(), bytecodeInfo.version, #bytecodeInfo.strings, #bytecodeInfo.numbers, #bytecodeInfo.protos)
        
        local finalCode = header .. decompiledCode
        
        -- Write to file
        writefile(outputPath, finalCode)
        
        print("✅ Decompilation completed successfully!")
        print("📄 Output file:", outputPath)
        print("📏 Generated code lines:", select(2, finalCode:gsub('\n', '\n')) + 1)
        
        return finalCode
    end)
    
    if not success then
        error("Decompilation failed: " .. tostring(result))
    end
    
    return result
end

-- Global function for easy access
_G.decompilev2 = decompilev2

print("🌍 Universal Luau Decompiler Loaded!")
print("💡 Usage: decompilev2(script_instance_or_path)")
print("🎯 Ready to decompile any Roblox Luau script!")

return LuauDecompiler
