using System;

namespace Agent
{
    public static class Utilities
    {
        public static bool Is64Bit
            => IntPtr.Size == 8;
    }
}
