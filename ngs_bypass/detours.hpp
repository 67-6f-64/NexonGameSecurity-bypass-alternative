#pragma once

#include "native.hpp"

namespace detours
{
	bool redirect(bool enable, void** function, void* redirection);
}