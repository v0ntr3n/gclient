#pragma once
#include "unzip/unzip.h"

namespace ax {
using ::unzFile;
using ::unz_global_info;
using ::unz_file_info;
using ::unzOpen;
using ::unzClose;
using ::unzGetGlobalInfo;
using ::unzGoToFirstFile;
using ::unzGoToNextFile;
using ::unzGetCurrentFileInfo;
using ::unzOpenCurrentFile;
using ::unzReadCurrentFile;
using ::unzCloseCurrentFile;
} // namespace ax
