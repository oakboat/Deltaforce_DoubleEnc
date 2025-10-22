#include "include.h"

//qq 群 849446012

struct c_vec3 { // basic vector struct
    float x, y, z;
};

typedef void (*DecFunc_t)(ULONG64 EncTable, void* data, DWORD size, WORD handle);
constexpr uintptr_t MAGIC_MASK = 0x0000FF0000000000;
constexpr uintptr_t MAGIC = 0x00004A0000000000;
ZydisDecoder g_decoder;
ZydisFormatter g_formatter;
uint64_t remote_value = 0;


// 获取寄存器值的辅助函数
uintptr_t GetRegisterValue(PCONTEXT context, ZydisRegister reg) {
    switch (reg) {
    case ZYDIS_REGISTER_RAX: return context->Rax;
    case ZYDIS_REGISTER_RBX: return context->Rbx;
    case ZYDIS_REGISTER_RCX: return context->Rcx;
    case ZYDIS_REGISTER_RDX: return context->Rdx;
    case ZYDIS_REGISTER_RSI: return context->Rsi;
    case ZYDIS_REGISTER_RDI: return context->Rdi;
    case ZYDIS_REGISTER_RBP: return context->Rbp;
    case ZYDIS_REGISTER_RSP: return context->Rsp;
    case ZYDIS_REGISTER_R8:  return context->R8;
    case ZYDIS_REGISTER_R9:  return context->R9;
    case ZYDIS_REGISTER_R10: return context->R10;
    case ZYDIS_REGISTER_R11: return context->R11;
    case ZYDIS_REGISTER_R12: return context->R12;
    case ZYDIS_REGISTER_R13: return context->R13;
    case ZYDIS_REGISTER_R14: return context->R14;
    case ZYDIS_REGISTER_R15: return context->R15;
    case ZYDIS_REGISTER_EAX: return context->Rax & 0xFFFFFFFF;
    case ZYDIS_REGISTER_EBX: return context->Rbx & 0xFFFFFFFF;
    case ZYDIS_REGISTER_ECX: return context->Rcx & 0xFFFFFFFF;
    case ZYDIS_REGISTER_EDX: return context->Rdx & 0xFFFFFFFF;
    case ZYDIS_REGISTER_ESI: return context->Rsi & 0xFFFFFFFF;
    case ZYDIS_REGISTER_EDI: return context->Rdi & 0xFFFFFFFF;
    case ZYDIS_REGISTER_EBP: return context->Rbp & 0xFFFFFFFF;
    case ZYDIS_REGISTER_ESP: return context->Rsp & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R8D: return context->R8 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R9D: return context->R9 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R10D: return context->R10 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R11D: return context->R11 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R12D: return context->R12 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R13D: return context->R13 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R14D: return context->R14 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R15D: return context->R15 & 0xFFFFFFFF;
    default: return 0;
    }
}

// 设置寄存器值的辅助函数
void SetRegisterValue(PCONTEXT context, ZydisRegister reg, uintptr_t value) {
    std::cout << "SetRegisterValue: " << value << "\n";
    switch (reg) {
    case ZYDIS_REGISTER_RAX: context->Rax = value; break;
    case ZYDIS_REGISTER_RBX: context->Rbx = value; break;
    case ZYDIS_REGISTER_RCX: context->Rcx = value; break;
    case ZYDIS_REGISTER_RDX: context->Rdx = value; break;
    case ZYDIS_REGISTER_RSI: context->Rsi = value; break;
    case ZYDIS_REGISTER_RDI: context->Rdi = value; break;
    case ZYDIS_REGISTER_RBP: context->Rbp = value; break;
    case ZYDIS_REGISTER_RSP: context->Rsp = value; break;
    case ZYDIS_REGISTER_R8:  context->R8 = value; break;
    case ZYDIS_REGISTER_R9:  context->R9 = value; break;
    case ZYDIS_REGISTER_R10: context->R10 = value; break;
    case ZYDIS_REGISTER_R11: context->R11 = value; break;
    case ZYDIS_REGISTER_R12: context->R12 = value; break;
    case ZYDIS_REGISTER_R13: context->R13 = value; break;
    case ZYDIS_REGISTER_R14: context->R14 = value; break;
    case ZYDIS_REGISTER_R15: context->R15 = value; break;
    case ZYDIS_REGISTER_EAX: context->Rax = (context->Rax & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_EBX: context->Rbx = (context->Rbx & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_ECX: context->Rcx = (context->Rcx & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_EDX: context->Rdx = (context->Rdx & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_ESI: context->Rsi = (context->Rsi & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_EDI: context->Rdi = (context->Rdi & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_EBP: context->Rbp = (context->Rbp & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_ESP: context->Rsp = (context->Rsp & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R8D: context->R8 = (context->R8 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R9D: context->R9 = (context->R9 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R10D: context->R10 = (context->R10 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R11D: context->R11 = (context->R11 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R12D: context->R12 = (context->R12 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R13D: context->R13 = (context->R13 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R14D: context->R14 = (context->R14 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R15D: context->R15 = (context->R15 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    default: break;
    }
}

bool FixBaseDisplacementMemoryAccess(PCONTEXT context, uintptr_t value) {
    uint8_t* instructionPointer = reinterpret_cast<uint8_t*>(context->Rip);

    // 解码指令
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&g_decoder, instructionPointer, ZYDIS_MAX_INSTRUCTION_LENGTH,
        &instruction, operands))) {
        return false;
    }

    std::cout << "解码指令: ";
    char buffer[256];
    ZydisFormatterFormatInstruction(&g_formatter, &instruction, operands,
        instruction.operand_count_visible, buffer, sizeof(buffer),
        reinterpret_cast<ZyanU64>(instructionPointer), nullptr);
    std::cout << buffer << std::endl;
   

    // 处理 MOV 指令
    if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;
        std::cout << "目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;
        if (operands[0].size == 64)
        {
            value |= MAGIC;
        }
        SetRegisterValue(context, destReg, value);
        context->Rip += instruction.length;
        return true;
    }

    // 处理 MOVZX 指令（零扩展移动）
    if (instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;

        // 获取源操作数的大小（通常是第二个操作数）
        ZyanU16 srcSize = operands[1].size;

        std::cout << "MOVZX 目标寄存器: " << ZydisRegisterGetString(destReg)
            << ", 源大小: " << srcSize << " 位, 目标大小: " << operands[0].size << " 位" << std::endl;

        // 根据源操作数大小进行零扩展
        uintptr_t extendedValue;
        switch (srcSize) {
        case 8:  // 从8位零扩展到目标大小
            extendedValue = value & 0xFF;
            break;
        case 16: // 从16位零扩展到目标大小
            extendedValue = value & 0xFFFF;
            break;
        case 32: // 从32位零扩展到64位
            extendedValue = value & 0xFFFFFFFF;
            break;
        default:
            std::cout << "不支持的源操作数大小: " << srcSize << std::endl;
            return false;
        }

        std::cout << std::hex << "MOVZX 操作: " << value << " -> " << extendedValue << std::endl;

        SetRegisterValue(context, destReg, extendedValue);
        context->Rip += instruction.length;
        return true;
    }

    // 处理 ADD 指令
    if (instruction.mnemonic == ZYDIS_MNEMONIC_ADD && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;
        std::cout << "ADD 目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;

        // 获取目标寄存器的当前值
        uintptr_t currentValue = GetRegisterValue(context, destReg);

        // 计算新的值：当前值 + 从内存读取的值
        uintptr_t newValue;

        // 根据操作数大小进行处理
        switch (operands[0].size) {
        case 8:  // 8位操作数
            newValue = (currentValue & 0xFFFFFFFFFFFFFF00) | ((currentValue + value) & 0xFF);
            break;
        case 16: // 16位操作数
            newValue = (currentValue & 0xFFFFFFFFFFFF0000) | ((currentValue + value) & 0xFFFF);
            break;
        case 32: // 32位操作数
            newValue = (currentValue & 0xFFFFFFFF00000000) | ((currentValue + value) & 0xFFFFFFFF);
            break;
        case 64: // 64位操作数
            newValue = currentValue + value;
            break;
        default:
            std::cout << "不支持的操作数大小: " << operands[0].size << std::endl;
            return false;
        }

        std::cout << std::hex << "ADD 操作: " << currentValue << " + " << value
            << " = " << newValue << std::endl;

        SetRegisterValue(context, destReg, newValue);
        context->Rip += instruction.length;
        return true;
    }

    // 处理 SUB 指令
    if (instruction.mnemonic == ZYDIS_MNEMONIC_SUB && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;
        std::cout << "SUB 目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;

        // 获取目标寄存器的当前值
        uintptr_t currentValue = GetRegisterValue(context, destReg);

        // 计算新的值：当前值 - 从内存读取的值
        uintptr_t newValue;

        // 根据操作数大小进行处理
        switch (operands[0].size) {
        case 8:  // 8位操作数
            newValue = (currentValue & 0xFFFFFFFFFFFFFF00) | ((currentValue - value) & 0xFF);
            break;
        case 16: // 16位操作数
            newValue = (currentValue & 0xFFFFFFFFFFFF0000) | ((currentValue - value) & 0xFFFF);
            break;
        case 32: // 32位操作数
            newValue = (currentValue & 0xFFFFFFFF00000000) | ((currentValue - value) & 0xFFFFFFFF);
            break;
        case 64: // 64位操作数
            newValue = currentValue - value;
            break;
        default:
            std::cout << "不支持的操作数大小: " << operands[0].size << std::endl;
            return false;
        }

        std::cout << std::hex << "SUB 操作: " << currentValue << " - " << value
            << " = " << newValue << std::endl;

        SetRegisterValue(context, destReg, newValue);
        context->Rip += instruction.length;
        return true;
    }

    // 处理 IMUL 指令（三操作数形式）
    if (instruction.mnemonic == ZYDIS_MNEMONIC_IMUL && instruction.operand_count_visible == 3) {
        // 检查操作数类型：寄存器，内存，立即数
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {

            ZydisRegister destReg = operands[0].reg.value;
            int64_t immediate = operands[2].imm.value.s;

            std::cout << "IMUL 目标寄存器: " << ZydisRegisterGetString(destReg)
                << ", 立即数: " << std::hex << immediate << std::endl;

            // 执行有符号乘法：目标寄存器 = 内存值 * 立即数
            int64_t result;

            // 根据操作数大小进行处理
            switch (operands[0].size) {
            case 8:  // 8位操作数
                result = (int8_t)value * (int8_t)immediate;
                break;
            case 16: // 16位操作数
                result = (int16_t)value * (int16_t)immediate;
                break;
            case 32: // 32位操作数
                result = (int32_t)value * (int32_t)immediate;
                break;
            case 64: // 64位操作数
                result = (int64_t)value * immediate;
                break;
            default:
                std::cout << "不支持的操作数大小: " << operands[0].size << std::endl;
                return false;
            }

            std::cout << std::hex << "IMUL 操作: " << value << " * " << immediate
                << " = " << result << std::endl;

            SetRegisterValue(context, destReg, (uintptr_t)result);
            context->Rip += instruction.length;
            return true;
        }
    }

    // 处理 IMUL 指令（两操作数形式）
    if (instruction.mnemonic == ZYDIS_MNEMONIC_IMUL && instruction.operand_count_visible == 2) {
        // 检查操作数类型：寄存器，内存
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {

            ZydisRegister destReg = operands[0].reg.value;

            std::cout << "IMUL 目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;

            // 获取目标寄存器的当前值
            int64_t currentValue = (int64_t)GetRegisterValue(context, destReg);

            // 执行有符号乘法：目标寄存器 = 当前值 * 内存值
            int64_t result;

            // 根据操作数大小进行处理
            switch (operands[0].size) {
            case 8:  // 8位操作数
                result = (int8_t)currentValue * (int8_t)value;
                break;
            case 16: // 16位操作数
                result = (int16_t)currentValue * (int16_t)value;
                break;
            case 32: // 32位操作数
                result = (int32_t)currentValue * (int32_t)value;
                break;
            case 64: // 64位操作数
                result = currentValue * (int64_t)value;
                break;
            default:
                std::cout << "不支持的操作数大小: " << operands[0].size << std::endl;
                return false;
            }

            std::cout << std::hex << "IMUL 操作: " << currentValue << " * " << value
                << " = " << (uintptr_t)result << std::endl;

            SetRegisterValue(context, destReg, (uintptr_t)result);
            context->Rip += instruction.length;
            return true;
        }
    }

    // 处理 AND 指令
    if (instruction.mnemonic == ZYDIS_MNEMONIC_AND && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;
        std::cout << "AND 目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;

        // 获取目标寄存器的当前值
        uintptr_t currentValue = GetRegisterValue(context, destReg);

        // 计算新的值：当前值 AND 从内存读取的值
        uintptr_t newValue = currentValue & value;

        std::cout << std::hex << "AND 操作: " << currentValue << " & " << value
            << " = " << newValue << std::endl;

        SetRegisterValue(context, destReg, newValue);
        context->Rip += instruction.length;
        return true;
    }

    // 处理 OR 指令
    if (instruction.mnemonic == ZYDIS_MNEMONIC_OR && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;
        std::cout << "OR 目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;

        // 获取目标寄存器的当前值
        uintptr_t currentValue = GetRegisterValue(context, destReg);

        // 计算新的值：当前值 OR 从内存读取的值
        uintptr_t newValue = currentValue | value;

        std::cout << std::hex << "OR 操作: " << currentValue << " | " << value
            << " = " << newValue << std::endl;

        SetRegisterValue(context, destReg, newValue);
        context->Rip += instruction.length;
        return true;
    }

    // 处理 XOR 指令
    if (instruction.mnemonic == ZYDIS_MNEMONIC_XOR && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;
        std::cout << "XOR 目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;

        // 获取目标寄存器的当前值
        uintptr_t currentValue = GetRegisterValue(context, destReg);

        // 计算新的值：当前值 XOR 从内存读取的值
        uintptr_t newValue = currentValue ^ value;

        std::cout << std::hex << "XOR 操作: " << currentValue << " ^ " << value
            << " = " << newValue << std::endl;

        SetRegisterValue(context, destReg, newValue);
        context->Rip += instruction.length;
        return true;
    }

    if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL && instruction.operand_count_visible == 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {

        std::cout << "处理间接 CALL 指令" << std::endl;

        // 从内存中读取的是函数指针
        uintptr_t functionPointer = value;

        std::cout << "函数指针: " << std::hex << functionPointer << std::endl;

        // 获取返回地址（下一条指令）
        uintptr_t returnAddress = context->Rip + instruction.length;

        // 将返回地址压入栈中
        context->Rsp -= 8; // 64位系统，栈是8字节对齐
        SIZE_T bytesWritten;
        if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)context->Rsp, &returnAddress, 8, &bytesWritten)) {
            std::cout << "压入返回地址失败" << std::endl;
            return false;
        }

        std::cout << "压入返回地址: " << std::hex << returnAddress
            << " 到栈地址: " << context->Rsp << std::endl;

        // 设置指令指针为函数地址
        context->Rip = functionPointer;

        std::cout << "跳转到函数: " << std::hex << functionPointer << std::endl;

        return true;
    }

    std::cout << "不支持的指令: " << ZydisMnemonicGetString(instruction.mnemonic) << std::endl;
    return false;
}

LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    PEXCEPTION_RECORD exceptionRecord = ExceptionInfo->ExceptionRecord;
    PCONTEXT context = ExceptionInfo->ContextRecord;

    // 检查是否为访问违规异常
    if (exceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    {
        uintptr_t faultAddress = (uintptr_t)exceptionRecord->ExceptionInformation[1];
        DWORD operationType = exceptionRecord->ExceptionInformation[0];

        std::cout << std::hex << "访问违规在地址: " << faultAddress
            << " 操作类型: " << (operationType == 0 ? "读取" : "写入")
            << " RIP: " << context->Rip << std::endl;

        if (((uintptr_t)faultAddress & MAGIC_MASK) == MAGIC)
        {
            faultAddress ^= MAGIC;
            remote_value = read<uintptr_t>(faultAddress);
            std::cout << "远程内容: " << remote_value << std::endl;
            
            if (FixBaseDisplacementMemoryAccess(context, remote_value)) {
                std::cout << "修复成功，继续执行" << std::endl;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else {
                std::cout << "修复失败" << std::endl;
            }
        }
       
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int32_t GetXorKey(int32_t Length) {
    int32_t Mode = Length % 9;
    int32_t ret = 0;

    switch (Mode) {
    case 0:
        ret = (Length + (Length & 31) + 128) | 127;
        break;
    case 1:
        ret = (Length + (Length ^ 223) + 128) | 127;
        break;
    case 2:
        ret = (Length + (Length | 207) + 128) | 127;
        break;
    case 3:
        ret = (33 * Length + 128) | 127;
        break;
    case 4:
        ret = (Length + (Length >> 2) + 128) | 127;
        break;
    case 5:
        ret = (3 * Length + 133) | 127;
        break;
    case 6:
        ret = (Length + ((4 * Length) | 5) + 128) | 127;
        break;
    case 7:
        ret = (Length + ((Length >> 4) | 7) + 128) | 127;
        break;
    case 8:
        ret = (Length + (Length ^ 12) + 128) | 127;
        break;
    default:
        ret = 0;
        break;
    }

    return ret;
}

std::string IndexToString(uint32_t index)
{
    char NameBuffer[1024]{};
    uint64_t ref = read<uint64_t>(0x154225A40 + (((uint32_t)(index >> 18) + 1) * 8));
    if (ref <= 0)
    {
        return "";
    }
    uint64_t NamePoolChunk = ref + (uint32_t)(2 * (index & 0x3FFFF));
    uint16_t Pool = read<uint16_t>(NamePoolChunk);
    if (Pool <= 0)
    {
        return "";
    }
    int32_t Length = (Pool >> 6) * ((Pool & 1) != 0 ? 2 : 1);
    if (Length < sizeof(NameBuffer))
    {
        Comm::ReadPhysicalMemory(uintptr_t(NamePoolChunk + 2), (UCHAR*)NameBuffer, Length);

        for (int i = 0; i < Length; ++i)
            NameBuffer[i] ^= GetXorKey(Length);

        NameBuffer[Length] = '\0';
    }
    return std::string(NameBuffer);
}

int main()
{
    std::ifstream file("DeltaForceClient-Win64-Shipping.exe", std::ios::in | std::ios::binary);
    if (!file.is_open())
    {
        std::cout << "打开文件失败\n";
        return 1;
    }
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    void* image = VirtualAlloc((void*)0x140000000, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image)
    {
        std::cout << "申请内存失败\n";
        return 1;
    }
    if (image != (void*)0x140000000)
    {
        std::cout << "申请内存位置不匹配\n";
        return 1;
    }
    if (!file.read(reinterpret_cast<char*>(image), size))
    {
        std::cout << "读取文件\n";
        return 1;
    }
    if (!AddVectoredExceptionHandler(1, VectoredExceptionHandler))
    {
        std::cout << "注册异常失败\n";
        return 1;
    }
    ZydisDecoderInit(&g_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&g_formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    init();

    DecFunc_t DecFunc = (DecFunc_t)0x1409FE730;
    int test = 1;
    //DecFunc(MAGIC | 0x154221CE8, &test, 4, 5);

    ULONG64 uWorld = read<ULONG64>(0x1538A5CC8);
    ULONG64 uLevels = read<ULONG64>(uWorld + 0x158);
    ULONG64 Ulevel = read<ULONG64>(uLevels);
    ULONG32 count = read<ULONG32>(Ulevel + 0xA0);
    ULONG64 Actoradd = read<ULONG64>(Ulevel + 0x98);
    for (ULONG32 i = 0; i < count; i++)
    {
        ULONG64 cplayer = read<ULONG64>(Actoradd + i * 8);
        if (!cplayer)
        {
            continue;
        }
        ULONG32 playerid = read<ULONG32>(cplayer + 0x1C);
        if (IndexToString(playerid) != "BP_DFMCharacter_C")
        {
            continue;
        }

        ULONG64 Mesh = read<ULONG64>(cplayer + 0x3D0);
        c_vec3 position = read<c_vec3>(Mesh + 0x210 + 0x10);
        uint16_t encHandler = read<uint16_t>(Mesh + 0x210 + 0x30);
        printf("原坐标 %f %f %f %x\n", position.x, position.y, position.z, encHandler);
        printf("原坐标 %x %x %x\n", *(int*)&position.x, *(int*)&position.y, *(int*)&position.z);
        if (encHandler != 0xffff)
        {
            DecFunc(MAGIC | 0x153E263A0, &position, 0xc, encHandler);
            printf("解密坐标 %f %f %f %x\n", position.x, position.y, position.z, encHandler);
            printf("解密坐标 %x %x %x\n", *(int*)&position.x, *(int*)&position.y, *(int*)&position.z);
        }
    }


    std::cin.get();
    std::cout << "Hello World!\n";
}