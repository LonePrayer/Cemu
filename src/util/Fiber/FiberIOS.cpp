#include "Fiber.h"
#include <atomic>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cstdio>

// iOS arm64 fiber implementation using custom assembly context switching.
// ucontext (makecontext/swapcontext) is non-functional on iOS arm64 (returns ENOTSUP).

struct FiberContext {
	// callee-saved GPRs
	uint64_t x19, x20, x21, x22, x23, x24, x25, x26, x27, x28;
	uint64_t fp;  // x29
	uint64_t lr;  // x30
	uint64_t sp;
	// callee-saved SIMD
	uint64_t d8, d9, d10, d11, d12, d13, d14, d15;
};

// Assembly context switch: saves current regs to *from, restores regs from *to, ret to new lr
extern "C" void fiber_swap_context(FiberContext* from, FiberContext* to);

// Trampoline: after first swap into a new fiber, x19=entryPoint, x20=userParam
extern "C" void fiber_trampoline();

__asm__(
	".text\n"
	".globl _fiber_swap_context\n"
	".p2align 2\n"
"_fiber_swap_context:\n"
	// save callee-saved to from (x0)
	"stp x19, x20, [x0, #0]\n"
	"stp x21, x22, [x0, #16]\n"
	"stp x23, x24, [x0, #32]\n"
	"stp x25, x26, [x0, #48]\n"
	"stp x27, x28, [x0, #64]\n"
	"stp x29, x30, [x0, #80]\n"
	"mov x9, sp\n"
	"str x9, [x0, #96]\n"
	"stp d8,  d9,  [x0, #104]\n"
	"stp d10, d11, [x0, #120]\n"
	"stp d12, d13, [x0, #136]\n"
	"stp d14, d15, [x0, #152]\n"
	// restore callee-saved from to (x1)
	"ldp x19, x20, [x1, #0]\n"
	"ldp x21, x22, [x1, #16]\n"
	"ldp x23, x24, [x1, #32]\n"
	"ldp x25, x26, [x1, #48]\n"
	"ldp x27, x28, [x1, #64]\n"
	"ldp x29, x30, [x1, #80]\n"
	"ldr x9, [x1, #96]\n"
	"mov sp, x9\n"
	"ldp d8,  d9,  [x1, #104]\n"
	"ldp d10, d11, [x1, #120]\n"
	"ldp d12, d13, [x1, #136]\n"
	"ldp d14, d15, [x1, #152]\n"
	"ret\n"

	".globl _fiber_trampoline\n"
	".p2align 2\n"
"_fiber_trampoline:\n"
	"mov x0, x20\n"   // userParam as first argument
	"blr x19\n"       // call entry point
	"brk #0\n"        // entry should never return
);

thread_local Fiber* sCurrentFiber{};

Fiber::Fiber(void(*FiberEntryPoint)(void* userParam), void* userParam, void* privateData) : m_privateData(privateData)
{
	FiberContext* ctx = (FiberContext*)calloc(1, sizeof(FiberContext));

	const size_t stackSize = 2 * 1024 * 1024;
	m_stackPtr = malloc(stackSize);

	// stack grows down; align to 16 bytes
	uint64_t stackTop = ((uint64_t)m_stackPtr + stackSize) & ~(uint64_t)15;

	ctx->x19 = (uint64_t)FiberEntryPoint;
	ctx->x20 = (uint64_t)userParam;
	ctx->sp  = stackTop;
	ctx->fp  = 0;
	ctx->lr  = (uint64_t)&fiber_trampoline;

	this->m_implData = (void*)ctx;
}

Fiber::Fiber(void* privateData) : m_privateData(privateData)
{
	FiberContext* ctx = (FiberContext*)calloc(1, sizeof(FiberContext));
	this->m_implData = (void*)ctx;
	m_stackPtr = nullptr;
}

Fiber::~Fiber()
{
	if(m_stackPtr)
		free(m_stackPtr);
	free(m_implData);
}

Fiber* Fiber::PrepareCurrentThread(void* privateData)
{
	cemu_assert_debug(sCurrentFiber == nullptr);
	sCurrentFiber = new Fiber(privateData);
	return sCurrentFiber;
}

void Fiber::Switch(Fiber& targetFiber)
{
	Fiber* leavingFiber = sCurrentFiber;
	sCurrentFiber = &targetFiber;
	std::atomic_thread_fence(std::memory_order_seq_cst);
	fiber_swap_context((FiberContext*)(leavingFiber->m_implData), (FiberContext*)(targetFiber.m_implData));
	std::atomic_thread_fence(std::memory_order_seq_cst);
}

void* Fiber::GetFiberPrivateData()
{
	return sCurrentFiber->m_privateData;
}
