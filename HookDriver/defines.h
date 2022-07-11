#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <IntSafe.h>
#include <ntimage.h>

#define print(fmt, ...) DbgPrintEx(0, 0, fmt, ##__VA_ARGS__)

#include "skCrypter.h"
#include "funcs.h"