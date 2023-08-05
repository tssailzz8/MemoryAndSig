using PeNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace 帝国
{
	public unsafe class MemHelper
	{
		#region imports

		[DllImport("kernel32.dll", SetLastError = true)]
		[SuppressUnmanagedCodeSecurity]
		private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
			int dwSize, out IntPtr lpNumberOfBytesRead);

		[DllImport("kernel32.dll", SetLastError = true)]
		[SuppressUnmanagedCodeSecurity]
		private static extern bool ReadProcessMemory(IntPtr hProcess,
			[Out][MarshalAs(UnmanagedType.AsAny)] object lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

		[DllImport("kernel32.dll", SetLastError = true)]
		[SuppressUnmanagedCodeSecurity]
		private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int dwSize,
			out IntPtr lpNumberOfBytesRead);

		[DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
		[SuppressUnmanagedCodeSecurity]
		internal static extern IntPtr MoveMemory(byte* dest, byte* src, int count);

		#endregion

		public Process target;
		public static IntPtr Handle { get; private set; }
		 int _dataLength { get;  set; }
		public long DataSectionOffset { get; private set; }
		/// <summary>
		/// The size of the .data section.
		/// </summary>
		public int DataSectionSize { get; private set; }
		public byte[] _data;
		public MemHelper(Process p)
		{

			target = p;
			BaseAddress = target.MainModule.BaseAddress;
			Handle = target.Handle;
			var pe = new PeFile(target.MainModule.FileName);
			var data = pe.ImageSectionHeaders.Where(i=>i.Name==".data").FirstOrDefault();
			DataSectionOffset = data.VirtualAddress;
			DataSectionSize = (int)data.VirtualSize;
			_dataLength = target.MainModule.ModuleMemorySize;
			_data = ReadBytes(BaseAddress, _dataLength);
		}
		List<int> HexToBytes(string hex)
		{
			List<int> bytes = new List<int>();

			for (int i = 0; i < hex.Length - 1;)
			{
				if (hex[i] == '?')
				{
					if (hex[i + 1] == '?')
						i++;
					i++;
					bytes.Add(-1);
					continue;
				}
				if (hex[i] == ' ')
				{
					i++;
					continue;
				}

				string byteString = hex.Substring(i, 2);
				var _byte = byte.Parse(byteString, NumberStyles.AllowHexSpecifier);
				bytes.Add(_byte);
				i += 2;
			}

			return bytes;
		}
		List<IntPtr> Find(List<int> pattern)
		{

			List<IntPtr> ret = new List<IntPtr>();
			uint plen = (uint)pattern.Count;
			var dataLength = _dataLength - plen;
			for (var i = 0; i < dataLength; i++)
			{
				if (ByteMatch(_data, (int)i, pattern))
					ret.Add((IntPtr)i);
			}
			return ret;
		}
		bool ByteMatch(byte[] bytes, int start, List<int> pattern)
		{
			for (int i = start, j = 0; j < pattern.Count; i++, j++)
			{
				if (pattern[j] == -1)
					continue;

				if (bytes[i] != pattern[j])
					return false;
			}
			return true;
		}
		public List<IntPtr> FindPattern(string pattern)
		{
			var results = Find(HexToBytes(pattern));
			for (int i = 0; i < results.Count; i++)
			{
				results[i] = BaseAddress + (int)results[i];

			}
			return results;
		}
		public IntPtr GetStaticAddressFromSig(string signature, int offset = 0)
		{
			IntPtr instrAddr = ScanText(signature);
			instrAddr = IntPtr.Add(instrAddr, offset);
			long bAddr = (long)BaseAddress;
			long num;
			do
			{
				instrAddr = IntPtr.Add(instrAddr, 1);
				num = ReadInt32(instrAddr) + (long)instrAddr + 4 - bAddr;
			}
			while (!(num >= DataSectionOffset && num <= DataSectionOffset + DataSectionSize));
			return IntPtr.Add(instrAddr, ReadInt32(instrAddr) + 4);
		}	
		public IntPtr ScanText(string pattern)
		{
			var results = FindPattern(pattern);
			if (results.Count > 1)
				throw new ArgumentException($"Provided pattern found {results.Count}, only a single result is acceptable");

			var scanRet = results[0];
			var insnByte = ReadByte(scanRet);
			if (insnByte == 0xE8 || insnByte == 0xE9)
				return ReadCallSig(scanRet);
			return scanRet;
		}
		private IntPtr ReadCallSig(IntPtr sigLocation)
		{
			var jumpOffset = ReadInt32(IntPtr.Add(sigLocation, 1));
			return IntPtr.Add(sigLocation, 5 + jumpOffset);
		}
		public IntPtr BaseAddress { get; }

		public byte[] ReadBytes(IntPtr address, int count)
		{
			var bytes = new byte[count];
			ReadProcessMemory(target.Handle, address, bytes, count, out var read);
			return bytes;
		}

		public T[] Read<T>(IntPtr address, int count) where T : struct
		{
			if (SizeCache<T>.TypeRequiresMarshal)
			{
				var ptr = Marshal.AllocHGlobal(SizeCache<T>.Size * count);
				Marshal.Copy(ReadBytes(address, SizeCache<T>.Size * count), 0, ptr, SizeCache<T>.Size * count);
				var arr = new T[count];
				// Unfortunate part of the marshaler, is that each instance needs to be pulled in separately.
				// Can't just do a bulk memcpy.
				for (var i = 0; i < count; i++) arr[i] = Marshal.PtrToStructure<T>(ptr + SizeCache<T>.Size * i);
				Marshal.FreeHGlobal(ptr);
				return arr;
			}

			if (count == 0) return new T[0];

			var ret = new T[count];
			fixed (byte* pB = ReadBytes(address, SizeCache<T>.Size * count))
			{
				var genericPtr = (byte*)SizeCache<T>.GetUnsafePtr(ref ret[0]);
				MoveMemory(genericPtr, pB, SizeCache<T>.Size * count);
			}

			return ret;
		}
		public Byte ReadByte(IntPtr address, int offset = 0) => Read<Byte>(IntPtr.Add(address, offset));
		public Int16 ReadInt16(IntPtr address, int offset = 0) => Read<Int16>(IntPtr.Add(address, offset));
		public Int32 ReadInt32(IntPtr address, int offset = 0) => Read<Int32>(IntPtr.Add(address, offset));
		public Int64 ReadInt64(IntPtr address, int offset = 0) => Read<Int64>(IntPtr.Add(address, offset));
		public IntPtr ReadIntPtr(IntPtr address, int offset = 0) => Read<IntPtr>(IntPtr.Add(address, offset));

		public T Read<T>(IntPtr address) where T : struct
		{
			if (SizeCache<T>.TypeRequiresMarshal)
			{
				var ptr = Marshal.AllocHGlobal(SizeCache<T>.Size);
				Marshal.Copy(ReadBytes(address, SizeCache<T>.Size), 0, ptr, SizeCache<T>.Size);
				var mret = Marshal.PtrToStructure<T>(ptr);
				Marshal.FreeHGlobal(ptr);
				return mret;
			}

			// OPTIMIZATION!
			var ret = new T();
			fixed (byte* b = ReadBytes(address, SizeCache<T>.Size))
			{
				var tPtr = (byte*)SizeCache<T>.GetUnsafePtr(ref ret);
				MoveMemory(tPtr, b, SizeCache<T>.Size);
			}

			return ret;
		}
		#region Write

		public void WriteByte(IntPtr baseAddress, byte data)
		{
			WriteBytes(baseAddress, new byte[] { (byte)data });
		}

		public void WriteInt16(IntPtr baseAddress, Int16 data)
		{
			WriteBytes(baseAddress, BitConverter.GetBytes(data));
		}

		public void WriteInt32(IntPtr baseAddress, Int32 data)
		{
			WriteBytes(baseAddress, BitConverter.GetBytes(data));
		}

		public void WriteInt64(IntPtr baseAddress, Int64 data)
		{
			WriteBytes(baseAddress, BitConverter.GetBytes(data));
		}
		/// <summary>
		/// Write a value to the specified offset, determined by type.
		/// </summary>
		/// <param name="offset">Offset to write to.</param>
		/// <param name="data">Value to write.</param>
		/// <exception cref="ArgumentException">Gets thrown, when the type to write is unsupported.</exception>
		public void Write(IntPtr offset, object data)
		{
			var @writeMethods = new Dictionary<Type, Action>
			{
				{typeof(byte[]), () => WriteBytes(offset, (byte[]) data)},
				{typeof(byte), () => WriteBytes(offset, new byte[] {(byte) data})},

				{typeof(char), () => WriteBytes(offset, new byte[] {(byte) data})},
				{typeof(short), () => WriteBytes(offset, BitConverter.GetBytes((short) data))},
				{typeof(ushort), () => WriteBytes(offset, BitConverter.GetBytes((ushort) data))},
				{typeof(int), () => WriteBytes(offset, BitConverter.GetBytes((int) data))},
				{typeof(uint), () => WriteBytes(offset, BitConverter.GetBytes((uint) data))},
				{typeof(long), () => WriteBytes(offset, BitConverter.GetBytes((long) data))},
				{typeof(ulong), () => WriteBytes(offset, BitConverter.GetBytes((ulong) data))},
				{typeof(float), () => WriteBytes(offset, BitConverter.GetBytes((float) data))},
				{typeof(double), () => WriteBytes(offset, BitConverter.GetBytes((double) data))},
			};

			if (@writeMethods.ContainsKey(data.GetType()))
				@writeMethods[data.GetType()]();
			else
				throw new ArgumentException("Unsupported type.");
		}

		public void Write<T>(IntPtr address, T value)
			where T : struct
		{
			if (address == IntPtr.Zero)
				return;

			int size = Marshal.SizeOf(typeof(T));
			IntPtr buffer = Marshal.AllocHGlobal(size);
			Marshal.StructureToPtr<T>(value, buffer, false);
			WriteProcessMemory(Handle, address, buffer, size, out _);
			Marshal.FreeHGlobal(buffer);
		}

		public bool WriteBytes(IntPtr address, byte[] buffer)
		{
			return WriteProcessMemory(Handle, address, buffer, buffer.Length, out _);
		}

		[DllImport("kernel32.dll")]
		public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);
		[SuppressUnmanagedCodeSecurity]
		[DllImport("kernel32.dll")]
		public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);
		#endregion
	}
}
